#!/usr/bin/env python3
"""DXM PC Setup GUI

PyQt-based Windows setup utility inspired by the provided batch script.
- Inspect button: generate/read-only system report.
- Run button: execute selected configuration actions.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence, overload

from PyQt5 import QtCore, QtGui, QtWidgets


APP_VERSION = "1.0.0"
APP_NAME = f"DXM - PC Setup v{APP_VERSION} (PyQt)"
CHECKLIST_WRAP_LINE_LEN = 64
STATUS_CHIP_STATES = ("PASS", "FAIL", "PENDING", "RUNNING")

from pccfg.domain.apply_catalog import APPLY_TASK_DEFINITIONS
from pccfg.domain.catalogs import INSTALL_APPS, MANUAL_INSTALL_APPS
from pccfg.domain.checklist import (
    CHECKLIST_FIELDS,
    CHECKLIST_LOG_FILE,
    CHECKLIST_TASK_MAX_LEN,
    FIELD_IDS_BY_LABEL,
    FIELDS_BY_ID,
    ITEM_IDS_BY_LABEL,
    ITEM_LABELS_BY_ID,
    SECTIONS,
)
from pccfg.domain.models import ApplyTask, ExecutionStep, InstallApp, ManualInstallApp
from pccfg.services.checklist_store import load_checklist_state, save_checklist_state

CLIENT_NAME_FIELD_ID = "client_name"
COMPUTER_ROLE_FIELD_ID = "computer_role"
NUMBERING_FIELD_ID = "numbering"
HOSTNAME_FIELD_ID = "hostname"
INVENTORY_ID_FIELD_ID = "inventory_id"
DATE_FIELD_ID = "date"
FILE_NAME_FIELD_ID = "file_name"

COMMAND_CANCEL_EXIT_CODE = -9
COMMAND_TIMEOUT_EXIT_CODE = -124
DEFAULT_INSPECT_TIMEOUT_SEC = 30
DEFAULT_APPLY_TIMEOUT_SEC = 120
DEFAULT_INSTALL_TIMEOUT_SEC = 1200


@overload
def run_command(command: str) -> tuple[int, str]: ...


@overload
def run_command(command: list[str]) -> tuple[int, str]: ...


def run_command(command: str | list[str]) -> tuple[int, str]:
    """Run command and return (return_code, output)."""
    return run_command_with_options(command)


def run_command_with_options(
    command: str | list[str],
    *,
    timeout_sec: float | None = None,
    cancel_requested: Callable[[], bool] | None = None,
    poll_interval_sec: float = 0.2,
) -> tuple[int, str]:
    """Run command with optional timeout/cancellation support."""
    args = command if isinstance(command, list) else shlex.split(command)
    proc = subprocess.Popen(
        args,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )

    deadline = None if timeout_sec is None else datetime.now().timestamp() + timeout_sec
    while True:
        if cancel_requested and cancel_requested():
            proc.terminate()
            try:
                stdout, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
            return COMMAND_CANCEL_EXIT_CODE, stdout.strip()

        if deadline is not None and datetime.now().timestamp() >= deadline:
            proc.terminate()
            try:
                stdout, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
            return COMMAND_TIMEOUT_EXIT_CODE, stdout.strip()

        rc = proc.poll()
        if rc is not None:
            stdout, _ = proc.communicate()
            return rc, stdout.strip()

        QtCore.QThread.msleep(max(1, int(poll_interval_sec * 1000)))


def format_command(args: list[str]) -> str:
    """Create a readable command line string for logging."""
    return subprocess.list2cmdline(args)


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Relaunch current script with elevation prompt on Windows."""
    if not is_windows():
        return False

    params = " ".join([f'"{arg}"' for arg in sys.argv])
    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            None,
            1,
        )
        return result > 32
    except Exception:
        return False


def load_stylesheet() -> str:
    """Load optional Qt stylesheet from ./style/app.qss."""
    stylesheet_path = Path(__file__).resolve().parent / "style" / "app.qss"
    if not stylesheet_path.exists():
        return ""
    return stylesheet_path.read_text(encoding="utf-8")


def compact_single_line(output: str) -> str:
    """Normalize command output into a readable single line."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return " | ".join(lines)


def parse_registry_value(output: str) -> str | None:
    """Extract the value payload from `reg query` output."""
    for raw_line in reversed(output.splitlines()):
        line = raw_line.strip()
        if not line or line.upper().startswith("HKEY"):
            continue
        parts = re.split(r"\s{2,}", line)
        if len(parts) >= 3:
            return parts[2]
    return None


def parse_active_power_plan(output: str) -> str:
    """Extract user-friendly active power plan details."""
    line = compact_single_line(output)
    if not line:
        return "Unable to query"
    plan_name_match = re.search(r"\(([^)]+)\)", line)
    guid_match = re.search(r"([0-9a-fA-F\-]{36})", line)
    plan_name = plan_name_match.group(1) if plan_name_match else "Unknown"
    if guid_match:
        return f"{plan_name} [{guid_match.group(1)}]"
    return plan_name


def parse_registry_int(raw_value: str | None) -> int | None:
    """Parse a registry DWORD string (hex or decimal) into an int."""
    if not raw_value:
        return None
    token = raw_value.strip().split()[0]
    try:
        return int(token, 0)
    except ValueError:
        return None


def parse_powercfg_indices(output: str) -> tuple[int | None, int | None]:
    """Extract AC/DC powercfg setting indices from command output."""
    ac_match = re.search(r"Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)", output)
    dc_match = re.search(r"Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)", output)
    ac_value = int(ac_match.group(1), 16) if ac_match else None
    dc_value = int(dc_match.group(1), 16) if dc_match else None
    return ac_value, dc_value


def status_tag(ok: bool) -> str:
    return "Ok" if ok else "Not Ok"


def shorten_task_label(label: str, max_len: int = CHECKLIST_TASK_MAX_LEN) -> str:
    """Keep checklist labels compact for better readability in the task column."""
    normalized = " ".join(label.split())
    if len(normalized) <= max_len:
        return normalized
    return f"{normalized[: max_len - 1].rstrip()}…"


def wrap_task_label(label: str, line_len: int = CHECKLIST_WRAP_LINE_LEN) -> str:
    """Wrap checklist labels to at most two lines without reserving extra height."""
    normalized = " ".join(label.split())
    if len(normalized) <= line_len:
        return normalized

    words = normalized.split(" ")
    first_line: list[str] = []
    for word in words:
        candidate = " ".join(first_line + [word]).strip()
        if len(candidate) > line_len and first_line:
            break
        first_line.append(word)

    first = " ".join(first_line).strip()
    remainder = normalized[len(first) :].strip()
    if not remainder:
        return first
    return f"{first}\n{shorten_task_label(remainder, max_len=line_len)}"


STATUS_LABEL_WIDTH = 28


def format_status_line(label: str, value: str, ok: bool, width: int = STATUS_LABEL_WIDTH) -> str:
    """Format status output with a consistently aligned value separator."""
    return f"{label:<{width}}: {value} [{status_tag(ok)}]"


def format_kv_line(label: str, value: str, width: int = 10) -> str:
    """Format label/value output with aligned colons for readability."""
    return f"{label:<{width}}: {value}"


def readable_timeout_seconds(seconds: int) -> str:
    """Format powercfg timeout values (reported in seconds) for display."""
    if seconds == 0:
        return "Disabled"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} sec"


def query_password_required_status(cancel_requested: Callable[[], bool] | None = None) -> bool | None:
    """Return whether the current Windows user requires a password."""
    username = os.environ.get("USERNAME", "").strip()
    if not username:
        return None

    _, output = run_command_with_options(
        ["net", "user", username],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.lower().startswith("password required"):
            continue
        if re.search(r"\byes\b", line, flags=re.IGNORECASE):
            return True
        if re.search(r"\bno\b", line, flags=re.IGNORECASE):
            return False

    return None


def detect_wifi_adapter(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    """Detect whether a Wi-Fi adapter exists."""
    command = (
        "$a = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | "
        "Where-Object { $_.InterfaceDescription -match 'Wi-Fi|Wireless|WLAN' -or $_.Name -match 'Wi-Fi|Wireless|WLAN' }; "
        "if ($a) { $a | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress }"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    adapters: list[str] = []
    raw = output.strip()
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = raw

        if isinstance(payload, str):
            adapters = [payload.strip()] if payload.strip() else []
        elif isinstance(payload, list):
            adapters = [str(item).strip() for item in payload if str(item).strip()]
    if adapters:
        return True, ", ".join(adapters)
    return False, "No Wi-Fi adapter found"


def detect_wifi_connection(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    """Detect Wi-Fi connection state and include SSID/signal when available."""
    rc, output = run_command_with_options(
        ["netsh", "wlan", "show", "interfaces"],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return None, "Unable to query"

    state_match = re.search(r"^\s*State\s*:\s*(.+)$", output, flags=re.IGNORECASE | re.MULTILINE)
    ssid_match = re.search(r"^\s*SSID\s*:\s*(.+)$", output, flags=re.IGNORECASE | re.MULTILINE)
    signal_match = re.search(r"^\s*Signal\s*:\s*(.+)$", output, flags=re.IGNORECASE | re.MULTILINE)

    state_value = state_match.group(1).strip() if state_match else "Unknown"
    connected = state_value.lower() == "connected"
    if connected:
        ssid = ssid_match.group(1).strip() if ssid_match else "Unknown"
        signal = signal_match.group(1).strip() if signal_match else "Unknown"
        return True, f"Connected ({ssid}, {signal})"
    return False, f"{state_value}"


def detect_internet_reachability(cancel_requested: Callable[[], bool] | None = None) -> tuple[bool | None, str]:
    """Detect internet reachability via DNS and ICMP checks."""
    dns_cmd = "Resolve-DnsName -Name microsoft.com -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty NameHost"
    ping_cmd = "Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet"
    dns_rc, dns_out = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", dns_cmd],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    ping_rc, ping_out = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", ping_cmd],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )

    if dns_rc != 0 and ping_rc != 0:
        return None, "Unable to query"

    dns_ok = bool(compact_single_line(dns_out))
    ping_ok = compact_single_line(ping_out).lower() == "true"
    reachable = dns_ok or ping_ok
    detail = f"DNS={'OK' if dns_ok else 'FAIL'}, Ping={'OK' if ping_ok else 'FAIL'}"
    return reachable, detail



def parse_json_payload(raw_output: str) -> list[dict[str, str]]:
    """Parse JSON produced by PowerShell's ConvertTo-Json output."""
    text = raw_output.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def guess_gpu_vendor(name: str) -> str:
    value = name.lower()
    if "nvidia" in value or "geforce" in value or "quadro" in value:
        return "NVIDIA"
    if "blackmagic" in value or "decklink" in value:
        return "Blackmagic"
    if "amd" in value or "radeon" in value:
        return "AMD"
    if "intel" in value:
        return "Intel"
    return "Unknown"


def get_vendor_driver_lookup_hint(vendor: str) -> str:
    links = {
        "NVIDIA": "https://www.nvidia.com/Download/index.aspx",
        "AMD": "https://www.amd.com/en/support/download/drivers.html",
        "Blackmagic": "https://www.blackmagicdesign.com/support/",
        "Intel": "https://www.intel.com/content/www/us/en/support/detect.html",
    }
    return links.get(vendor, "Vendor support page")


def format_driver_date(raw_date: str) -> str:
    """Normalize WMI driver date values to YYYY-MM-DD when possible."""
    value = raw_date.strip()
    if not value:
        return "Unknown"

    ms_epoch = re.search(r"/Date\((\d+)", value)
    if ms_epoch:
        try:
            return datetime.fromtimestamp(int(ms_epoch.group(1)) / 1000).strftime("%Y-%m-%d")
        except (OverflowError, ValueError, OSError):
            return value

    iso_like = re.match(r"(\d{4})(\d{2})(\d{2})", value)
    if iso_like:
        return f"{iso_like.group(1)}-{iso_like.group(2)}-{iso_like.group(3)}"
    return value


def format_memory_gib(capacity_bytes: int) -> str:
    """Format bytes as GiB with one decimal place."""
    return f"{capacity_bytes / (1024 ** 3):.1f} GiB"


def is_target_video_device(name: str, pnp_device_id: str) -> bool:
    """Keep only physical target vendors requested by the workflow."""
    text = f"{name} {pnp_device_id}".lower()
    vendor_match = any(token in text for token in ("nvidia", "geforce", "quadro", "amd", "radeon", "blackmagic", "decklink"))
    virtual_tokens = ("virtual", "parsec", "vorpx", "meta", "mridd")
    return vendor_match and not any(token in text for token in virtual_tokens)


def query_registry_dword(key_path: str, value_name: str, cancel_requested: Callable[[], bool] | None = None) -> int | None:
    _, output = run_command_with_options(
        ["reg", "query", key_path, "/v", value_name],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    return parse_registry_int(parse_registry_value(output))


def query_power_setting_indices(
    subgroup_guid: str,
    setting_guid: str,
    cancel_requested: Callable[[], bool] | None = None,
) -> tuple[int | None, int | None]:
    _, output = run_command_with_options(
        ["powercfg", "/query", "scheme_current", subgroup_guid, setting_guid],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    return parse_powercfg_indices(output)


def format_power_dual_status(
    label: str,
    subgroup_guid: str,
    setting_guid: str,
    expected_ac: int,
    expected_dc: int,
    value_formatter: Callable[[int], str],
    cancel_requested: Callable[[], bool] | None = None,
) -> str:
    ac_value, dc_value = query_power_setting_indices(subgroup_guid, setting_guid, cancel_requested)
    if ac_value is None or dc_value is None:
        return format_status_line(label, "Unable to query", False)

    ok = ac_value == expected_ac and dc_value == expected_dc
    if ac_value == dc_value:
        current_value = value_formatter(ac_value)
        expected_value = value_formatter(expected_ac)
        display = current_value if ok else f"{current_value} (expected {expected_value})"
        return format_status_line(label, display, ok)

    display = f"AC={value_formatter(ac_value)}, DC={value_formatter(dc_value)}"
    if not ok:
        expected_display = f"AC={value_formatter(expected_ac)}, DC={value_formatter(expected_dc)}"
        display = f"{display} (expected {expected_display})"
    return format_status_line(label, display, ok)


def collect_apply_status_checks(cancel_requested: Callable[[], bool] | None = None) -> list[tuple[str, str, bool]]:
    """Collect APPLY option status checks as structured tuples."""
    checks: list[tuple[str, str, bool]] = []

    _, active_plan_out = run_command_with_options(
        ["powercfg", "/getactivescheme"],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    active_plan = parse_active_power_plan(active_plan_out)
    high_perf_guid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    active_line = compact_single_line(active_plan_out).lower()
    active_ok = high_perf_guid in active_line or "high performance" in active_line
    checks.append(("Active power plan", active_plan, active_ok))

    power_checks = (
        ("Sleep timeout", "SUB_SLEEP", "STANDBYIDLE", 0, 0),
        ("Hibernate timeout", "SUB_SLEEP", "HIBERNATEIDLE", 0, 0),
        ("Disk timeout", "SUB_DISK", "DISKIDLE", 0, 0),
        ("Monitor timeout", "SUB_VIDEO", "VIDEOIDLE", 1800, 1800),
    )
    for label, subgroup, setting, expected_ac, expected_dc in power_checks:
        ac_value, dc_value = query_power_setting_indices(subgroup, setting, cancel_requested)
        if ac_value is None or dc_value is None:
            checks.append((label, "Unable to query", False))
            continue
        ok = ac_value == expected_ac and dc_value == expected_dc
        if ac_value == dc_value:
            current_value = readable_timeout_seconds(ac_value)
            expected_value = readable_timeout_seconds(expected_ac)
            display = current_value if ok else f"{current_value} (expected {expected_value})"
            checks.append((label, display, ok))
            continue

        display = f"AC={readable_timeout_seconds(ac_value)}, DC={readable_timeout_seconds(dc_value)}"
        if not ok:
            expected_display = f"AC={readable_timeout_seconds(expected_ac)}, DC={readable_timeout_seconds(expected_dc)}"
            display = f"{display} (expected {expected_display})"
        checks.append((label, display, ok))

    usb_suspend = query_power_setting_indices(
        "2a737441-1930-4402-8d77-b2bebba308a3",
        "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
        cancel_requested,
    )
    if usb_suspend[0] is None or usb_suspend[1] is None:
        checks.append(("USB selective suspend", "Unable to query", False))
    else:
        usb_ok = usb_suspend[0] == 0 and usb_suspend[1] == 0
        checks.append(("USB selective suspend", f"AC={usb_suspend[0]}, DC={usb_suspend[1]}", usb_ok))

    fast_startup = query_registry_dword(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
        "HiberbootEnabled",
        cancel_requested,
    )
    if fast_startup is None:
        checks.append(("Fast Startup", "Unable to query", False))
    else:
        checks.append(("Fast Startup", "Disabled" if fast_startup == 0 else "Enabled", fast_startup == 0))

    game_dvr = query_registry_dword("HKCU\\System\\GameConfigStore", "GameDVR_Enabled", cancel_requested)
    app_capture = query_registry_dword(
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR",
        "AppCaptureEnabled",
        cancel_requested,
    )
    allow_game_dvr = query_registry_dword(
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR",
        "AllowGameDVR",
        cancel_requested,
    )
    game_dvr_ok = game_dvr == 0 and app_capture == 0 and allow_game_dvr == 0
    if game_dvr is None or app_capture is None or allow_game_dvr is None:
        checks.append(("Game DVR", "Unable to query", False))
    else:
        checks.append(
            (
                "Game DVR",
                f"GameDVR_Enabled={game_dvr}, AppCaptureEnabled={app_capture}, AllowGameDVR={allow_game_dvr}",
                game_dvr_ok,
            )
        )

    visual_fx = query_registry_dword(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects",
        "VisualFXSetting",
        cancel_requested,
    )
    if visual_fx is None:
        checks.append(("Visual effects", "Unable to query", False))
    else:
        visual_fx_value = "Best performance" if visual_fx == 2 else f"Custom ({visual_fx})"
        checks.append(("Visual effects", visual_fx_value, visual_fx == 2))

    thumbnails = query_registry_dword(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "IconsOnly",
        cancel_requested,
    )
    if thumbnails is None:
        checks.append(("Thumbnail previews", "Unable to query", False))
    else:
        checks.append(("Thumbnail previews", "Enabled" if thumbnails == 0 else "Disabled", thumbnails == 0))

    toast_enabled = query_registry_dword(
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
        "ToastEnabled",
        cancel_requested,
    )
    if toast_enabled is None:
        checks.append(("Toast notifications", "Unable to query", False))
    else:
        checks.append(("Toast notifications", "Disabled" if toast_enabled == 0 else "Enabled", toast_enabled == 0))

    notification_center = query_registry_dword(
        "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
        "DisableNotificationCenter",
        cancel_requested,
    )
    if notification_center is None:
        checks.append(("Notification Center", "Unable to query", False))
    else:
        checks.append(("Notification Center", "Disabled" if notification_center == 1 else "Enabled", notification_center == 1))

    password_required = query_password_required_status(cancel_requested)
    if password_required is None:
        checks.append(("Windows password", "Unable to query", False))
    else:
        checks.append(("Windows password", "Protected" if password_required else "Not protected", password_required))

    return checks


def build_apply_status_lines(rename_target: str, cancel_requested: Callable[[], bool] | None = None) -> list[str]:
    lines: list[str] = [
        format_status_line(label, value, ok)
        for label, value, ok in collect_apply_status_checks(cancel_requested)
    ]

    if rename_target:
        current_name = os.environ.get("COMPUTERNAME", "Unknown")
        lines.append(
            format_status_line(
                "Rename computer",
                f"Current={current_name}, Target={rename_target}",
                current_name.lower() == rename_target.lower(),
            )
        )
    return lines


class SetupWorker(QtCore.QObject):
    log_line = QtCore.pyqtSignal(str)
    step_started = QtCore.pyqtSignal(str)
    step_finished = QtCore.pyqtSignal(str, bool)
    checklist_status = QtCore.pyqtSignal(str, str, bool, str)
    completed = QtCore.pyqtSignal(bool, str)

    def __init__(
        self,
        *,
        mode: str,
        rename_target: str = "",
        apply_steps: Sequence[ExecutionStep] | None = None,
        app_steps: Sequence[ExecutionStep] | None = None,
    ) -> None:
        super().__init__()
        self._mode = mode
        self._rename_target = rename_target
        self._apply_steps = list(apply_steps or [])
        self._app_steps = list(app_steps or [])
        self._cancel_requested = False

    @QtCore.pyqtSlot()
    def request_cancel(self) -> None:
        self._cancel_requested = True

    def _cancelled(self) -> bool:
        return self._cancel_requested

    @QtCore.pyqtSlot()
    def run(self) -> None:
        try:
            if self._mode == "inspect":
                self._run_inspect()
            else:
                self._run_apply()
        except Exception as exc:  # safeguard background thread
            self.log_line.emit(f"[ERROR] Unexpected failure: {exc}")
            self.completed.emit(False, "failed")

    def _run_inspect(self) -> None:
        self.log_line.emit("=" * 60)
        self.log_line.emit(f"{APP_NAME} - INSPECT REPORT")
        self.log_line.emit("=" * 60)
        self.log_line.emit(format_kv_line("Time", datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        self.log_line.emit(format_kv_line("Computer", os.environ.get('COMPUTERNAME', 'Unknown')))
        self.log_line.emit("")

        self.step_started.emit("APPLY option status")
        for line in build_apply_status_lines(self._rename_target, self._cancelled):
            self.log_line.emit(line)
        self.step_finished.emit("APPLY option status", True)

        inspect_apply_task_map = {
            "Active power plan": "Power plan: Performance (High performance)",
            "Sleep timeout": "Sleep: Never (AC)",
            "Hibernate timeout": "Hibernate: Off",
            "Disk timeout": "Disk sleep: Never",
            "Monitor timeout": "Monitor timeout: 30 min",
            "Fast Startup": "Disable Fast Startup",
            "Game DVR": "Disable Game Bar / Game DVR",
            "Visual effects": "Enable Best performance + keep thumbnails",
            "Toast notifications": "Disable Windows notifications (current user)",
            "Notification Center": "Disable Windows notifications (current user)",
        }
        notification_results: list[bool] = []
        for status_label, value, ok in collect_apply_status_checks(self._cancelled):
            task_label = inspect_apply_task_map.get(status_label)
            if not task_label:
                continue
            if task_label == "Disable Windows notifications (current user)":
                notification_results.append(ok)
                continue
            self.checklist_status.emit(task_label, "PASS" if ok else "FAIL", ok, f"Inspect: {status_label}={value}")

        if notification_results:
            notifications_ok = all(notification_results)
            self.checklist_status.emit(
                "Disable Windows notifications (current user)",
                "PASS" if notifications_ok else "FAIL",
                notifications_ok,
                "Inspect: Toast notifications and Notification Center",
            )

        self.log_line.emit("")

        if self._cancelled():
            self.completed.emit(False, "cancelled")
            return

        inspect_checks = {
            "Install network drivers (LAN/10GbE/Wi-Fi)": "RUNNING",
            "Test Wi-Fi": "RUNNING",
            "Test remote connection": "RUNNING",
        }
        for task_label, status in inspect_checks.items():
            self.checklist_status.emit(task_label, status, False, "Inspect in progress")

        if not is_windows():
            self.log_line.emit("[ERROR] This tool is intended for Windows.")
            self.completed.emit(False, "failed")
            return

        self.step_started.emit("System")
        code, os_name = run_command_with_options(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).Caption"], timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC, cancel_requested=self._cancelled)
        _, os_ver = run_command_with_options(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).Version"], timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC, cancel_requested=self._cancelled)
        _, os_build = run_command_with_options(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).BuildNumber"], timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC, cancel_requested=self._cancelled)
        _, os_ubr = run_command_with_options(["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "UBR"], timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC, cancel_requested=self._cancelled)
        _, os_display = run_command_with_options(["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "DisplayVersion"], timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC, cancel_requested=self._cancelled)
        if code == 0:
            self.log_line.emit("System")
            self.log_line.emit("-" * 60)
            self.log_line.emit(format_kv_line("OS", compact_single_line(os_name)))
            self.log_line.emit(format_kv_line("Version", compact_single_line(os_ver)))
            self.log_line.emit(format_kv_line("Build", compact_single_line(os_build)))
            ubr_value = parse_registry_int(parse_registry_value(os_ubr))
            display_value = parse_registry_value(os_display)
            if display_value:
                self.log_line.emit(format_kv_line("Release", display_value))
            if ubr_value is not None:
                current_full_build = f"{compact_single_line(os_build)}.{ubr_value}"
                self.log_line.emit(format_kv_line("Full build", current_full_build))
        else:
            self.log_line.emit(format_kv_line("OS", "unable to query"))
        self.log_line.emit(format_kv_line("Admin", 'YES' if is_admin() else 'NO'))
        self.step_finished.emit("System", code == 0)
        self.log_line.emit("")

        if self._cancelled():
            self.completed.emit(False, "cancelled")
            return

        self.step_started.emit("Memory")
        self.log_line.emit("Memory")
        self.log_line.emit("-" * 60)
        memory_cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer,PartNumber,Capacity,ConfiguredClockSpeed,Speed | ConvertTo-Json -Compress",
        ]
        _, memory_out = run_command_with_options(memory_cmd, timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC, cancel_requested=self._cancelled)
        modules = parse_json_payload(memory_out)
        if modules:
            capacities: list[int] = []
            speeds: list[int] = []
            for module in modules:
                try:
                    capacities.append(int(str(module.get("Capacity", "0")).strip() or "0"))
                except ValueError:
                    capacities.append(0)

                configured_speed = str(module.get("ConfiguredClockSpeed", "")).strip()
                fallback_speed = str(module.get("Speed", "")).strip()
                speed_value = configured_speed or fallback_speed
                try:
                    if speed_value:
                        speeds.append(int(speed_value))
                except ValueError:
                    continue

            module_count = len(modules)
            total_capacity = sum(capacities)
            self.log_line.emit(format_kv_line("Modules", str(module_count)))
            if total_capacity > 0:
                self.log_line.emit(format_kv_line("Quantity", format_memory_gib(total_capacity)))
            else:
                self.log_line.emit(format_kv_line("Quantity", "Unknown"))

            if speeds:
                unique_speeds = sorted(set(speeds))
                if len(unique_speeds) == 1:
                    speed_text = f"{unique_speeds[0]} MT/s"
                else:
                    speed_text = ", ".join(f"{speed} MT/s" for speed in unique_speeds)
                self.log_line.emit(format_kv_line("Speed", speed_text))
            else:
                self.log_line.emit(format_kv_line("Speed", "Unknown"))
        else:
            self.log_line.emit(format_kv_line("RAM", "Unable to query"))
        self.log_line.emit("")
        self.step_finished.emit("Memory", bool(modules))

        if self._cancelled():
            self.completed.emit(False, "cancelled")
            return

        self.step_started.emit("Target video cards")
        self.log_line.emit("Target video cards (NVIDIA / AMD / Blackmagic)")
        self.log_line.emit("-" * 60)
        gpu_cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,DriverDate,PNPDeviceID | ConvertTo-Json -Compress",
        ]
        _, gpu_out = run_command_with_options(gpu_cmd, timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC, cancel_requested=self._cancelled)
        gpus = [gpu for gpu in parse_json_payload(gpu_out) if is_target_video_device(str(gpu.get("Name", "")), str(gpu.get("PNPDeviceID", "")))]
        if gpus:
            self.log_line.emit(format_kv_line("Found", f"{len(gpus)} matching device(s)"))
            for gpu in gpus:
                name = str(gpu.get("Name", "Unknown")).strip() or "Unknown"
                version = str(gpu.get("DriverVersion", "Unknown")).strip() or "Unknown"
                date = format_driver_date(str(gpu.get("DriverDate", "")))
                vendor = guess_gpu_vendor(name)
                lookup = get_vendor_driver_lookup_hint(vendor)
                self.log_line.emit(format_kv_line("GPU", name))
                self.log_line.emit(format_kv_line("  Driver", version))
                self.log_line.emit(format_kv_line("  Date", date))
                self.log_line.emit(format_kv_line("  Latest", f"check {vendor} site -> {lookup}"))
        else:
            self.log_line.emit(format_kv_line("GPU", "No NVIDIA/AMD/Blackmagic video card detected"))
        self.log_line.emit("")
        self.step_finished.emit("Target video cards", True)

        if self._cancelled():
            self.completed.emit(False, "cancelled")
            return

        self.step_started.emit("Connectivity")
        self.log_line.emit("Connectivity")
        self.log_line.emit("-" * 60)

        wifi_adapter_ok, wifi_adapter_detail = detect_wifi_adapter(self._cancelled)
        wifi_connected_ok, wifi_connected_detail = detect_wifi_connection(self._cancelled)
        internet_ok, internet_detail = detect_internet_reachability(self._cancelled)

        if wifi_adapter_ok is None:
            self.log_line.emit(format_status_line("Wi-Fi adapter", wifi_adapter_detail, False))
            self.checklist_status.emit("Install network drivers (LAN/10GbE/Wi-Fi)", "PENDING", False, wifi_adapter_detail)
        else:
            self.log_line.emit(format_status_line("Wi-Fi adapter", wifi_adapter_detail, wifi_adapter_ok))
            self.checklist_status.emit(
                "Install network drivers (LAN/10GbE/Wi-Fi)",
                "PASS" if wifi_adapter_ok else "FAIL",
                wifi_adapter_ok,
                wifi_adapter_detail,
            )

        if wifi_connected_ok is None:
            self.log_line.emit(format_status_line("Wi-Fi connection", wifi_connected_detail, False))
            self.checklist_status.emit("Test Wi-Fi", "PENDING", False, wifi_connected_detail)
        else:
            self.log_line.emit(format_status_line("Wi-Fi connection", wifi_connected_detail, wifi_connected_ok))
            self.checklist_status.emit(
                "Test Wi-Fi",
                "PASS" if wifi_connected_ok else "FAIL",
                wifi_connected_ok,
                wifi_connected_detail,
            )

        if internet_ok is None:
            self.log_line.emit(format_status_line("Internet", internet_detail, False))
            self.checklist_status.emit("Test remote connection", "PENDING", False, internet_detail)
        else:
            self.log_line.emit(format_status_line("Internet", internet_detail, internet_ok))
            self.checklist_status.emit(
                "Test remote connection",
                "PASS" if internet_ok else "FAIL",
                internet_ok,
                internet_detail,
            )

        self.log_line.emit("")
        self.step_finished.emit("Connectivity", True)
        self.completed.emit(True, "done")

    def _run_apply(self) -> None:
        self.log_line.emit("=== DXM PC Setup (APPLY) ===")
        self.log_line.emit(format_kv_line("Time", datetime.now().strftime('%Y%m%d_%H%M%S')))
        self.log_line.emit(format_kv_line("Computer", os.environ.get('COMPUTERNAME', 'Unknown')))
        self.log_line.emit("")

        if not is_windows():
            self.log_line.emit("[ERROR] This tool is intended for Windows.")
            self.completed.emit(False, "failed")
            return
        if not is_admin():
            self.log_line.emit("[ERROR] Please run this script as Administrator for APPLY mode.")
            self.completed.emit(False, "failed")
            return

        if not self._apply_steps and not self._app_steps:
            self.log_line.emit("No APPLY options or application installs selected.")
            self.completed.emit(False, "failed")
            return

        for idx, step in enumerate(self._apply_steps, start=1):
            if self._cancelled():
                self.completed.emit(False, "cancelled")
                return

            step_name = f"[{idx}/{len(self._apply_steps)}] {step.label}"
            self.step_started.emit(step_name)
            self.log_line.emit(step_name)
            ok = True
            for cmd in step.commands:
                rc, out = run_command_with_options(cmd, timeout_sec=DEFAULT_APPLY_TIMEOUT_SEC, cancel_requested=self._cancelled)
                self.log_line.emit(f"  $ {format_command(cmd)}")
                if rc == COMMAND_CANCEL_EXIT_CODE:
                    self.log_line.emit("    -> CANCELLED")
                    self.step_finished.emit(step_name, False)
                    self.completed.emit(False, "cancelled")
                    return
                if rc == COMMAND_TIMEOUT_EXIT_CODE:
                    ok = False
                    self.log_line.emit(f"    -> FAIL (timeout after {DEFAULT_APPLY_TIMEOUT_SEC}s)")
                else:
                    ok = ok and rc == 0
                    status = "OK" if rc == 0 else f"FAIL (exit {rc})"
                    self.log_line.emit(f"    -> {status}")
                if out:
                    self.log_line.emit(f"    {out}")
            self.log_line.emit("")
            self.step_finished.emit(step_name, ok)

        if self._app_steps:
            self.log_line.emit("Applications installation")
            self.log_line.emit("-" * 30)
            for idx, step in enumerate(self._app_steps, start=1):
                if self._cancelled():
                    self.completed.emit(False, "cancelled")
                    return

                step_name = f"[{idx}/{len(self._app_steps)}] {step.label}"
                self.step_started.emit(step_name)
                self.log_line.emit(step_name)
                cmd = step.commands[0]
                rc, out = run_command_with_options(cmd, timeout_sec=DEFAULT_INSTALL_TIMEOUT_SEC, cancel_requested=self._cancelled)
                self.log_line.emit(f"  $ {format_command(cmd)}")
                if rc == COMMAND_CANCEL_EXIT_CODE:
                    self.log_line.emit("    -> CANCELLED")
                    self.step_finished.emit(step_name, False)
                    self.completed.emit(False, "cancelled")
                    return
                if rc == COMMAND_TIMEOUT_EXIT_CODE:
                    self.log_line.emit(f"    -> FAIL (timeout after {DEFAULT_INSTALL_TIMEOUT_SEC}s)")
                    self.step_finished.emit(step_name, False)
                else:
                    status = "OK" if rc == 0 else f"FAIL (exit {rc})"
                    self.log_line.emit(f"    -> {status}")
                    self.step_finished.emit(step_name, rc == 0)
                if out:
                    self.log_line.emit(f"    {out}")
                self.log_line.emit("")

        self.log_line.emit("DONE. Reboot is recommended (required if computer rename was applied).")
        self.completed.emit(True, "done")


class MainWindow(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(920, 700)

        self.select_all_checkbox = QtWidgets.QCheckBox("Select all APPLY options")
        self.select_all_checkbox.setChecked(True)

        self.inspect_button = QtWidgets.QPushButton("Inspect")
        self.run_button = QtWidgets.QPushButton("Run")
        self.clear_button = QtWidgets.QPushButton("Clear Output")
        self.new_install_button = QtWidgets.QPushButton("New install")
        self.export_installation_report_button = QtWidgets.QPushButton("Export installation report")
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.save_report_button = QtWidgets.QPushButton("Save Report (TXT)")

        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)

        self.apply_tasks = self._build_tasks()
        self.task_checkboxes: dict[str, QtWidgets.QCheckBox] = {}
        self.install_apps = self._build_install_apps()
        self.manual_install_apps = self._build_manual_install_apps()
        self.app_checkboxes: dict[str, QtWidgets.QCheckBox] = {}
        self.rename_input = QtWidgets.QLineEdit()
        self.rename_input.setPlaceholderText("Auto-generated from checklist hostname")
        self.rename_input.setReadOnly(True)
        self.rename_input.setEnabled(False)

        self.tasks_group = QtWidgets.QGroupBox("APPLY Options")
        self.tasks_layout = QtWidgets.QVBoxLayout(self.tasks_group)
        for task in self.apply_tasks:
            cb = QtWidgets.QCheckBox(task.label)
            cb.setChecked(True)
            self.task_checkboxes[task.key] = cb
            if task.key == "rename_pc":
                rename_row = QtWidgets.QHBoxLayout()
                rename_row.addWidget(cb)
                rename_row.addWidget(self.rename_input)
                self.tasks_layout.addLayout(rename_row)
                cb.toggled.connect(self.rename_input.setEnabled)
                self.rename_input.setEnabled(cb.isChecked())
            else:
                self.tasks_layout.addWidget(cb)

        self.apps_group = QtWidgets.QGroupBox("Applications")
        self.apps_layout = QtWidgets.QVBoxLayout(self.apps_group)
        current_category: str | None = None
        for app in self.install_apps:
            if app.category != current_category:
                current_category = app.category
                category_label = QtWidgets.QLabel(current_category)
                font = category_label.font()
                font.setBold(True)
                category_label.setFont(font)
                self.apps_layout.addWidget(category_label)
            cb = QtWidgets.QCheckBox(app.label)
            cb.setChecked(False)
            self.app_checkboxes[app.key] = cb
            self.apps_layout.addWidget(cb)
        self.apps_layout.addStretch(1)

        self.manual_group = QtWidgets.QGroupBox("Manual install")
        self.manual_layout = QtWidgets.QVBoxLayout(self.manual_group)
        current_manual_category: str | None = None
        for manual_app in self.manual_install_apps:
            if manual_app.category != current_manual_category:
                current_manual_category = manual_app.category
                category_label = QtWidgets.QLabel(current_manual_category)
                font = category_label.font()
                font.setBold(True)
                category_label.setFont(font)
                self.manual_layout.addWidget(category_label)

            app_row = QtWidgets.QHBoxLayout()
            app_row.addWidget(QtWidgets.QLabel(manual_app.label), stretch=1)

            open_button = QtWidgets.QPushButton("Open website")
            open_button.clicked.connect(
                lambda _checked=False, app=manual_app: self._open_manual_install_link(app.label, app.website_url)
            )
            app_row.addWidget(open_button)
            self.manual_layout.addLayout(app_row)
        self.manual_layout.addStretch(1)

        self.installation_checklist_group = QtWidgets.QGroupBox("Installation PC checklist")
        checklist_group_layout = QtWidgets.QVBoxLayout(self.installation_checklist_group)

        self.installation_checklist_progress = QtWidgets.QLabel("0/0 completed")
        checklist_group_layout.addWidget(self.installation_checklist_progress)

        self.installation_checklist_tree = QtWidgets.QTreeWidget()
        self.installation_checklist_tree.setObjectName("installationChecklistTree")
        self.installation_checklist_tree.setColumnCount(3)
        self.installation_checklist_tree.setHeaderLabels(["Task", "Status", "Info"])
        self.installation_checklist_tree.setRootIsDecorated(False)
        self.installation_checklist_tree.setMouseTracking(True)
        self.installation_checklist_tree.setAlternatingRowColors(True)
        self.installation_checklist_tree.setUniformRowHeights(False)
        self.installation_checklist_tree.setIndentation(0)
        self.installation_checklist_tree.setTextElideMode(QtCore.Qt.ElideNone)
        self.installation_checklist_tree.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.installation_checklist_tree.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.installation_checklist_tree.header().setStretchLastSection(False)
        self.installation_checklist_tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        self.installation_checklist_tree.header().setSectionResizeMode(1, QtWidgets.QHeaderView.Fixed)
        self.installation_checklist_tree.header().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        self.installation_checklist_tree.setColumnWidth(1, 110)
        checklist_group_layout.addWidget(self.installation_checklist_tree, stretch=1)

        self.checklist_status_bar = QtWidgets.QLabel("Ready")
        self.checklist_status_bar.setObjectName("checklistStatusBar")
        self.checklist_status_bar.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.checklist_status_bar.setMinimumHeight(24)
        self.checklist_status_bar.setWordWrap(False)
        checklist_group_layout.addWidget(self.checklist_status_bar)

        checklist_buttons_row = QtWidgets.QHBoxLayout()
        checklist_buttons_row.addWidget(self.new_install_button)
        checklist_buttons_row.addWidget(self.export_installation_report_button)
        checklist_group_layout.addLayout(checklist_buttons_row)

        self._is_loading_checklist_state = False
        self._is_autofilling_checklist_info = False
        self._last_autofill_values: dict[str, str] = {}
        self.installation_checklist_items: list[QtWidgets.QTreeWidgetItem] = []
        self.checklist_item_by_id: dict[str, QtWidgets.QTreeWidgetItem] = {}
        self.checklist_status_chips: dict[str, QtWidgets.QLabel] = {}
        self.checklist_runtime_status: dict[str, tuple[str, str]] = {}
        self.checklist_info_inputs: dict[str, QtWidgets.QWidget] = {}
        for section in SECTIONS:
            section_header = QtWidgets.QTreeWidgetItem([section.label, "", ""])
            section_header.setFlags(section_header.flags() & ~QtCore.Qt.ItemIsSelectable)
            section_header.setFirstColumnSpanned(True)
            section_font = section_header.font(0)
            section_font.setBold(True)
            section_header.setFont(0, section_font)
            self.installation_checklist_tree.addTopLevelItem(section_header)

            for section_item in section.items:
                wrapped_label = wrap_task_label(section_item.label)
                checklist_item = QtWidgets.QTreeWidgetItem([wrapped_label, "", ""])
                checklist_item.setFlags(checklist_item.flags() | QtCore.Qt.ItemIsUserCheckable)
                checklist_item.setCheckState(0, QtCore.Qt.Unchecked)
                checklist_item.setData(0, QtCore.Qt.UserRole, section_item.item_id)
                checklist_item.setToolTip(0, section_item.label)
                self.installation_checklist_tree.addTopLevelItem(checklist_item)
                self.installation_checklist_items.append(checklist_item)
                self.checklist_item_by_id[section_item.item_id] = checklist_item

                status_chip = QtWidgets.QLabel("PENDING")
                status_chip.setObjectName("checklistStatusChip")
                status_chip.setProperty("chipStatus", "PENDING")
                status_chip.setAlignment(QtCore.Qt.AlignCenter)
                self.installation_checklist_tree.setItemWidget(checklist_item, 1, status_chip)
                self.checklist_status_chips[section_item.item_id] = status_chip
                self.checklist_runtime_status[section_item.item_id] = ("PENDING", "Waiting")

                field = FIELDS_BY_ID.get(section_item.item_id)
                if field is None:
                    continue

                if field.field_type == "date":
                    value_input = QtWidgets.QDateEdit()
                    value_input.setDisplayFormat("yyyy-MM-dd")
                    value_input.setCalendarPopup(True)
                    value_input.setDate(QtCore.QDate.currentDate())
                    value_input.dateChanged.connect(
                        lambda _value, field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
                    )
                elif field.field_type == "numbering":
                    value_input = QtWidgets.QComboBox()
                    value_input.addItems([f"{number:02d}" for number in range(1, 100)])
                    value_input.currentTextChanged.connect(
                        lambda _value, field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
                    )
                else:
                    value_input = QtWidgets.QLineEdit()
                    value_input.setPlaceholderText("Add details")
                    if field.field_id == HOSTNAME_FIELD_ID:
                        value_input.setReadOnly(True)
                        value_input.setPlaceholderText("Auto-generated")
                    value_input.textChanged.connect(
                        lambda _value, field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
                    )

                self.installation_checklist_tree.setItemWidget(checklist_item, 2, value_input)
                self.checklist_info_inputs[field.field_id] = value_input

        self.installation_checklist_tree.itemChanged.connect(self._on_installation_checklist_item_changed)
        self.installation_checklist_tree.currentItemChanged.connect(self._on_checklist_item_focus_changed)
        self.installation_checklist_tree.itemEntered.connect(self._on_checklist_item_hovered)
        self.installation_checklist_tree.resizeColumnToContents(2)
        self.installation_checklist_tree.setColumnWidth(1, 110)
        self._load_installation_checklist_state()
        self._update_installation_checklist_progress()
        self.installation_checklist_group.setMinimumWidth(820)

        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(self.inspect_button)
        btn_row.addWidget(self.run_button)
        btn_row.addWidget(self.clear_button)
        btn_row.addWidget(self.cancel_button)

        bottom_row = QtWidgets.QHBoxLayout()
        bottom_row.addStretch(1)
        bottom_row.addWidget(self.save_report_button)

        layout = QtWidgets.QHBoxLayout(self)

        left_column = QtWidgets.QVBoxLayout()
        left_column.addWidget(self.select_all_checkbox)
        left_column.addWidget(self.tasks_group)
        left_column.addLayout(btn_row)
        left_column.addWidget(self.output)
        left_column.addLayout(bottom_row)

        right_column = QtWidgets.QHBoxLayout()
        right_column.addWidget(self.apps_group, stretch=1)
        right_column.addWidget(self.manual_group, stretch=1)
        right_column.addWidget(self.installation_checklist_group, stretch=4)

        layout.addLayout(left_column, stretch=3)
        layout.addLayout(right_column, stretch=2)

        self.select_all_checkbox.stateChanged.connect(self._toggle_all)
        self.inspect_button.clicked.connect(self._run_inspect)
        self.run_button.clicked.connect(self._run_apply)
        self.clear_button.clicked.connect(self.output.clear)
        self.new_install_button.clicked.connect(self._start_new_install)
        self.export_installation_report_button.clicked.connect(self._export_installation_report)
        self.cancel_button.clicked.connect(self._request_cancel)
        self.save_report_button.clicked.connect(self._save_report_txt)

        self._worker_thread: QtCore.QThread | None = None
        self._worker: SetupWorker | None = None

        self._apply_checklist_autofill()

    def _on_installation_checklist_item_changed(self, _item: QtWidgets.QTreeWidgetItem | None = None, _column: int = 0) -> None:
        if _item is not None and _column == 0:
            task_id = _item.data(0, QtCore.Qt.UserRole)
            if isinstance(task_id, str) and task_id:
                if _item.checkState(0) == QtCore.Qt.Checked:
                    self._set_checklist_item_status(task_id, "PASS", "Checked")
                elif self.checklist_runtime_status.get(task_id, ("", ""))[0] in {"PASS", "PENDING"}:
                    self._set_checklist_item_status(task_id, "PENDING", "Waiting")

        self._update_installation_checklist_progress()
        if self._is_loading_checklist_state:
            return
        self._save_installation_checklist_state()

    def _on_checklist_item_focus_changed(
        self,
        current: QtWidgets.QTreeWidgetItem | None,
        _previous: QtWidgets.QTreeWidgetItem | None,
    ) -> None:
        self._set_checklist_status_message(current)

    def _on_checklist_item_hovered(self, item: QtWidgets.QTreeWidgetItem, _column: int) -> None:
        self._set_checklist_status_message(item)

    def _set_checklist_status_message(self, item: QtWidgets.QTreeWidgetItem | None) -> None:
        if item is None:
            self.checklist_status_bar.setText("Ready")
            return

        task_id = item.data(0, QtCore.Qt.UserRole)
        if not isinstance(task_id, str) or not task_id:
            self.checklist_status_bar.setText(item.text(0))
            return
        task_label = ITEM_LABELS_BY_ID.get(task_id, task_id)
        runtime_state = self.checklist_runtime_status.get(task_id, ("PENDING", "Waiting"))
        self.checklist_status_bar.setText(f"{task_label} [{runtime_state[0]}] - {runtime_state[1]}")

    def _on_checklist_info_field_changed(self, field_id: str) -> None:
        if self._is_loading_checklist_state:
            return

        source_fields = {
            CLIENT_NAME_FIELD_ID,
            COMPUTER_ROLE_FIELD_ID,
            NUMBERING_FIELD_ID,
            INVENTORY_ID_FIELD_ID,
            DATE_FIELD_ID,
        }
        if field_id in source_fields and not self._is_autofilling_checklist_info:
            self._apply_checklist_autofill()

        if field_id == HOSTNAME_FIELD_ID:
            self.rename_input.setText(self._get_checklist_info_text(HOSTNAME_FIELD_ID))

        self._save_installation_checklist_state()

    def _apply_checklist_autofill(self) -> None:
        hostname_text = self._build_hostname_value()
        file_name_text = self._build_file_name_value()
        self._autofill_line_edit(HOSTNAME_FIELD_ID, hostname_text)
        self._autofill_line_edit(FILE_NAME_FIELD_ID, file_name_text)
        self.rename_input.setText(hostname_text)

    def _set_checklist_item_status(self, task_id: str, status: str, detail: str) -> None:
        if status not in STATUS_CHIP_STATES:
            status = "PENDING"

        chip = self.checklist_status_chips.get(task_id)
        if chip is not None:
            chip.setText(status)
            chip.setProperty("chipStatus", status)
            chip.style().unpolish(chip)
            chip.style().polish(chip)
            chip.update()

        self.checklist_runtime_status[task_id] = (status, detail)

    @QtCore.pyqtSlot(str, str, bool, str)
    def _on_inspect_checklist_status(self, task_label: str, status: str, should_check: bool, detail: str) -> None:
        task_id = ITEM_IDS_BY_LABEL.get(task_label, task_label)
        item = self.checklist_item_by_id.get(task_id)
        if item is None:
            return
        self._set_checklist_item_status(task_id, status, detail)
        if should_check and status == "PASS":
            item.setCheckState(0, QtCore.Qt.Checked)
        elif status == "FAIL":
            item.setCheckState(0, QtCore.Qt.Unchecked)
        elif status == "PENDING" and item.checkState(0) != QtCore.Qt.Checked:
            item.setCheckState(0, QtCore.Qt.Unchecked)

    def _autofill_line_edit(self, field_label: str, proposed_value: str) -> None:
        widget = self.checklist_info_inputs.get(field_label)
        if not isinstance(widget, QtWidgets.QLineEdit):
            return

        current_value = widget.text().strip()
        last_autofill_value = self._last_autofill_values.get(field_label, "")
        should_overwrite = not current_value or current_value == last_autofill_value
        if not should_overwrite:
            return

        self._is_autofilling_checklist_info = True
        try:
            widget.setText(proposed_value)
        finally:
            self._is_autofilling_checklist_info = False
        self._last_autofill_values[field_label] = proposed_value

    def _build_hostname_value(self) -> str:
        client_name = self._to_pascal_case_alnum(self._get_checklist_info_text(CLIENT_NAME_FIELD_ID))
        role_value = self._to_alnum(self._get_checklist_info_text(COMPUTER_ROLE_FIELD_ID)).upper()
        numbering_value = self._normalize_numbering_value(self._get_checklist_info_text(NUMBERING_FIELD_ID))

        role_prefix = role_value[:2]
        hostname_parts = [part for part in [client_name, role_prefix, numbering_value] if part]
        return "-".join(hostname_parts)

    @staticmethod
    def _to_alnum(value: str) -> str:
        return "".join(char for char in value if char.isalnum())

    @classmethod
    def _normalize_numbering_value(cls, value: str) -> str:
        alnum_value = cls._to_alnum(value)
        if alnum_value.isdigit():
            numeric_value = int(alnum_value)
            if 1 <= numeric_value <= 99:
                return f"{numeric_value:02d}"
        return alnum_value

    @classmethod
    def _to_pascal_case_alnum(cls, value: str) -> str:
        words = re.split(r"[^A-Za-z0-9]+", value)
        return "".join(cls._to_alnum(word).capitalize() for word in words if word)

    def _build_file_name_value(self) -> str:
        date_widget = self.checklist_info_inputs.get(DATE_FIELD_ID)
        if isinstance(date_widget, QtWidgets.QDateEdit):
            date_value = date_widget.date().toString("yyyyMMdd")
        else:
            date_value = datetime.now().strftime("%Y%m%d")

        inventory_id = self._get_checklist_info_text(INVENTORY_ID_FIELD_ID)
        main_parts = [part for part in [date_value, inventory_id] if part]
        base_name = "_".join(main_parts) if main_parts else date_value
        return f"{base_name}_Step_001.jpg"

    def _get_checklist_info_text(self, field_label: str) -> str:
        widget = self.checklist_info_inputs.get(field_label)
        if isinstance(widget, QtWidgets.QLineEdit):
            return widget.text().strip()
        if isinstance(widget, QtWidgets.QComboBox):
            return widget.currentText().strip()
        return ""

    def _update_installation_checklist_progress(self) -> None:
        total = len(self.installation_checklist_items)
        done = sum(item.checkState(0) == QtCore.Qt.Checked for item in self.installation_checklist_items)
        self.installation_checklist_progress.setText(f"{done}/{total} completed")

    def _save_installation_checklist_state(self) -> None:
        if self._is_loading_checklist_state:
            return

        checklist_state = {
            str(item.data(0, QtCore.Qt.UserRole) or item.text(0)): item.checkState(0) == QtCore.Qt.Checked
            for item in self.installation_checklist_items
        }
        checklist_info = {
            key: self._read_checklist_info_value(widget)
            for key, widget in self.checklist_info_inputs.items()
        }
        save_checklist_state(CHECKLIST_LOG_FILE, checklist_state, checklist_info)

    def _load_installation_checklist_state(self) -> None:
        try:
            persisted_items, persisted_info = load_checklist_state(CHECKLIST_LOG_FILE)
        except (json.JSONDecodeError, OSError):
            return

        self._is_loading_checklist_state = True
        try:
            for item in self.installation_checklist_items:
                key = str(item.data(0, QtCore.Qt.UserRole) or item.text(0))
                checked = bool(persisted_items.get(key, False))
                item.setCheckState(0, QtCore.Qt.Checked if checked else QtCore.Qt.Unchecked)

            for key, widget in self.checklist_info_inputs.items():
                self._set_checklist_info_value(widget, persisted_info.get(key, ""))
        finally:
            self._is_loading_checklist_state = False

        for key in (HOSTNAME_FIELD_ID, FILE_NAME_FIELD_ID):
            value = self._get_checklist_info_text(key)
            self._last_autofill_values[key] = value

        self._apply_checklist_autofill()

    def _start_new_install(self) -> None:
        self._is_loading_checklist_state = True
        try:
            for item in self.installation_checklist_items:
                item.setCheckState(0, QtCore.Qt.Unchecked)
                task_id = item.data(0, QtCore.Qt.UserRole)
                if isinstance(task_id, str):
                    self._set_checklist_item_status(task_id, "PENDING", "Waiting")
            for widget in self.checklist_info_inputs.values():
                self._set_checklist_info_value(widget, "")
        finally:
            self._is_loading_checklist_state = False

        self._last_autofill_values.clear()
        self._apply_checklist_autofill()

        self._update_installation_checklist_progress()

        try:
            CHECKLIST_LOG_FILE.unlink(missing_ok=True)
        except OSError as exc:
            QtWidgets.QMessageBox.warning(
                self,
                "New install",
                f"Could not remove checklist log file:\n{exc}",
            )
            return

        self._append("[INFO] New install started: checklist reset and log cleared.")

    def _save_report_txt(self) -> None:
        report_content = self.output.toPlainText().strip()
        if not report_content:
            QtWidgets.QMessageBox.information(
                self,
                "Save Report",
                "There is no report output to save yet.",
            )
            return

        default_name = f"dxm_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        selected_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save report as TXT",
            default_name,
            "Text Files (*.txt);;All Files (*)",
        )
        if not selected_path:
            return

        try:
            Path(selected_path).write_text(f"{report_content}\n", encoding="utf-8")
        except OSError as exc:
            QtWidgets.QMessageBox.critical(
                self,
                "Save Report",
                f"Failed to save report:\n{exc}",
            )
            return

        self._append(f"[INFO] Report saved to: {selected_path}")

    def _export_installation_report(self) -> None:
        total = len(self.installation_checklist_items)
        completed = sum(item.checkState(0) == QtCore.Qt.Checked for item in self.installation_checklist_items)

        checklist_items_by_label = {
            ITEM_LABELS_BY_ID.get(str(item.data(0, QtCore.Qt.UserRole)), str(item.data(0, QtCore.Qt.UserRole))): item
            for item in self.installation_checklist_items
        }

        lines: list[str] = [
            "DXM Installation Report",
            f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Progress: {completed}/{total} completed",
            "",
            "Checklist info",
        ]

        for field in CHECKLIST_FIELDS:
            value = self._read_checklist_info_value(self.checklist_info_inputs[field.field_id])
            lines.append(f"- {field.label}: {value or '-'}")

        lines.append("")
        lines.append("Checklist tasks")
        for section in SECTIONS:
            lines.append(section.label)
            for section_item in section.items:
                item = checklist_items_by_label.get(section_item.label)
                if item is None:
                    continue
                status = "[x]" if item.checkState(0) == QtCore.Qt.Checked else "[ ]"
                lines.append(f"  {status} {section_item.label}")
            lines.append("")

        default_name = f"installation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        selected_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export installation report",
            default_name,
            "Text Files (*.txt);;All Files (*)",
        )
        if not selected_path:
            return

        try:
            Path(selected_path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        except OSError as exc:
            QtWidgets.QMessageBox.critical(
                self,
                "Export installation report",
                f"Failed to export installation report:\n{exc}",
            )
            return

        self._append(f"[INFO] Installation report exported to: {selected_path}")

    def _read_checklist_info_value(self, widget: QtWidgets.QWidget) -> str:
        if isinstance(widget, QtWidgets.QLineEdit):
            return widget.text().strip()
        if isinstance(widget, QtWidgets.QComboBox):
            return widget.currentText().strip()
        if isinstance(widget, QtWidgets.QDateEdit):
            return widget.date().toString("yyyy-MM-dd")
        return ""

    def _set_checklist_info_value(self, widget: QtWidgets.QWidget, value: str) -> None:
        if isinstance(widget, QtWidgets.QLineEdit):
            widget.setText(value)
            return
        if isinstance(widget, QtWidgets.QComboBox):
            normalized_value = self._normalize_numbering_value(value)
            index = widget.findText(normalized_value)
            widget.setCurrentIndex(index if index >= 0 else 0)
            return
        if isinstance(widget, QtWidgets.QDateEdit):
            parsed_date = QtCore.QDate.fromString(value, "yyyy-MM-dd")
            widget.setDate(parsed_date if parsed_date.isValid() else QtCore.QDate.currentDate())

    def _build_tasks(self) -> list[ApplyTask]:
        tasks = [
            ApplyTask(
                key=definition.key,
                label=definition.label,
                action=lambda commands=definition.commands: [list(command) for command in commands],
            )
            for definition in APPLY_TASK_DEFINITIONS
        ]
        tasks.append(
            ApplyTask(
                key="rename_pc",
                label="Rename computer",
                action=self._rename_computer_action,
            )
        )
        return tasks

    def _build_install_apps(self) -> list[InstallApp]:
        return list(INSTALL_APPS)

    def _build_manual_install_apps(self) -> list[ManualInstallApp]:
        return list(MANUAL_INSTALL_APPS)

    def _open_manual_install_link(self, app_label: str, url: str) -> None:
        opened = QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
        if not opened:
            self._append(f"[WARN] Unable to open {app_label} website: {url}")

    def _append(self, text: str = "") -> None:
        self.output.appendPlainText(text)
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

    def _toggle_all(self, state: int) -> None:
        checked = state == QtCore.Qt.Checked
        for cb in self.task_checkboxes.values():
            cb.setChecked(checked)
        for cb in self.app_checkboxes.values():
            cb.setChecked(checked)

    def _set_execution_state(self, running: bool) -> None:
        self.inspect_button.setEnabled(not running)
        self.run_button.setEnabled(not running)
        self.cancel_button.setEnabled(running)
        self.select_all_checkbox.setEnabled(not running)
        self.tasks_group.setEnabled(not running)
        self.apps_group.setEnabled(not running)
        self.manual_group.setEnabled(not running)
        self.save_report_button.setEnabled(not running)
        self.new_install_button.setEnabled(not running)
        self.export_installation_report_button.setEnabled(not running)

    def _start_worker(self, worker: SetupWorker) -> None:
        self._worker_thread = QtCore.QThread(self)
        self._worker = worker
        self._worker.moveToThread(self._worker_thread)

        worker.log_line.connect(self._append)
        worker.checklist_status.connect(self._on_inspect_checklist_status)
        worker.completed.connect(self._on_worker_completed)

        self._worker_thread.started.connect(worker.run)
        worker.completed.connect(self._worker_thread.quit)
        worker.completed.connect(worker.deleteLater)
        self._worker_thread.finished.connect(self._worker_thread.deleteLater)

        self._set_execution_state(True)
        self._worker_thread.start()

    def _request_cancel(self) -> None:
        if not hasattr(self, '_worker') or self._worker is None:
            return
        self._append('[INFO] Cancel requested. Stopping after current command...')
        self._worker.request_cancel()
        self.cancel_button.setEnabled(False)

    def _on_worker_completed(self, success: bool, reason: str) -> None:
        if reason == 'cancelled':
            self._append('[INFO] Operation cancelled.')
        elif not success:
            self._append('[INFO] Operation finished with errors.')
        self._set_execution_state(False)
        self._worker = None
        self._worker_thread = None

    def _run_inspect(self) -> None:
        worker = SetupWorker(mode='inspect', rename_target=self.rename_input.text().strip())
        self._start_worker(worker)

    def _build_apply_execution_plan(self) -> tuple[list[ExecutionStep], list[ExecutionStep]] | None:
        selected_steps: list[ExecutionStep] = []
        rename_requested = self.task_checkboxes['rename_pc'].isChecked()
        rename_name = self.rename_input.text().strip()

        for task in self.apply_tasks:
            if not self.task_checkboxes[task.key].isChecked():
                continue
            if task.key == 'rename_pc' and not rename_name:
                self._append('Rename computer step skipped (name is empty).')
                self._append()
                continue
            commands = task.action()
            if task.key == 'rename_pc' and rename_requested and rename_name and not commands:
                return None
            if commands:
                selected_steps.append(ExecutionStep(label=task.label, commands=commands))

        selected_apps = [a for a in self.install_apps if self.app_checkboxes[a.key].isChecked()]
        app_steps: list[ExecutionStep] = []
        for app in selected_apps:
            cmd = [
                'winget',
                'install',
                '--id',
                app.winget_id,
                '-e',
                '--silent',
                '--disable-interactivity',
                '--accept-package-agreements',
                '--accept-source-agreements',
            ]
            app_steps.append(ExecutionStep(label=app.label, commands=[cmd]))

        return selected_steps, app_steps

    def _run_apply(self) -> None:
        plan = self._build_apply_execution_plan()
        if plan is None:
            return

        selected_steps, app_steps = plan
        if not selected_steps and not app_steps:
            self._append('No APPLY options or application installs selected.')
            return

        worker = SetupWorker(
            mode='apply',
            rename_target=self.rename_input.text().strip(),
            apply_steps=selected_steps,
            app_steps=app_steps,
        )
        self._start_worker(worker)

    def _rename_computer_action(self) -> list[list[str]]:
        new_name = self.rename_input.text().strip()
        if not new_name:
            return []

        if len(new_name) > 15 or not re.fullmatch(r"[A-Za-z0-9-]+", new_name) or new_name.endswith("-"):
            QtWidgets.QMessageBox.critical(
                self,
                "Invalid computer name",
                "Computer name must be 1-15 characters, use only A-Z, a-z, 0-9, or '-', and cannot end with '-'.",
            )
            return []

        ps_command = f"Rename-Computer -NewName '{new_name}' -Force"
        return [["powershell", "-NoProfile", "-Command", ps_command]]


def main() -> int:
    if is_windows() and not is_admin():
        if relaunch_as_admin():
            return 0
        print("[ERROR] Administrator privileges are required to start this app.")
        return 1

    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(load_stylesheet())
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
