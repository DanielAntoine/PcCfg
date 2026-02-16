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

from PyQt5 import QtCore, QtWidgets


APP_VERSION = "1.0.0"
APP_NAME = f"DXM - PC Setup v{APP_VERSION} (PyQt)"


@dataclass
class ApplyTask:
    key: str
    label: str
    action: Callable[[], list[list[str]]]


@dataclass
class InstallApp:
    key: str
    label: str
    winget_id: str
    category: str


@dataclass
class ExecutionStep:
    label: str
    commands: list[list[str]]


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


def build_apply_status_lines(rename_target: str, cancel_requested: Callable[[], bool] | None = None) -> list[str]:
    lines: list[str] = []

    _, active_plan_out = run_command_with_options(
        ["powercfg", "/getactivescheme"],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    active_plan = parse_active_power_plan(active_plan_out)
    high_perf_guid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    active_line = compact_single_line(active_plan_out).lower()
    active_ok = high_perf_guid in active_line or "high performance" in active_line
    lines.append(format_status_line("Active power plan", active_plan, active_ok))

    lines.append(
        format_power_dual_status(
            "Sleep timeout",
            "SUB_SLEEP",
            "STANDBYIDLE",
            expected_ac=0,
            expected_dc=0,
            value_formatter=readable_timeout_seconds,
            cancel_requested=cancel_requested,
        )
    )
    lines.append(
        format_power_dual_status(
            "Hibernate timeout",
            "SUB_SLEEP",
            "HIBERNATEIDLE",
            expected_ac=0,
            expected_dc=0,
            value_formatter=readable_timeout_seconds,
            cancel_requested=cancel_requested,
        )
    )
    lines.append(
        format_power_dual_status(
            "Disk timeout",
            "SUB_DISK",
            "DISKIDLE",
            expected_ac=0,
            expected_dc=0,
            value_formatter=readable_timeout_seconds,
            cancel_requested=cancel_requested,
        )
    )
    lines.append(
        format_power_dual_status(
            "Monitor timeout",
            "SUB_VIDEO",
            "VIDEOIDLE",
            expected_ac=1800,
            expected_dc=1800,
            value_formatter=readable_timeout_seconds,
            cancel_requested=cancel_requested,
        )
    )

    usb_suspend = query_power_setting_indices(
        "2a737441-1930-4402-8d77-b2bebba308a3",
        "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
        cancel_requested,
    )
    if usb_suspend[0] is None or usb_suspend[1] is None:
        lines.append(format_status_line("USB selective suspend", "Unable to query", False))
    else:
        usb_ok = usb_suspend[0] == 0 and usb_suspend[1] == 0
        lines.append(format_status_line("USB selective suspend", f"AC={usb_suspend[0]}, DC={usb_suspend[1]}", usb_ok))

    fast_startup = query_registry_dword(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
        "HiberbootEnabled",
        cancel_requested,
    )
    if fast_startup is None:
        lines.append(format_status_line("Fast Startup", "Unable to query", False))
    else:
        lines.append(format_status_line("Fast Startup", "Disabled" if fast_startup == 0 else "Enabled", fast_startup == 0))

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
        lines.append(format_status_line("Game DVR", "Unable to query", False))
    else:
        lines.append(
            format_status_line(
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
        lines.append(format_status_line("Visual effects", "Unable to query", False))
    else:
        visual_fx_value = "Best performance" if visual_fx == 2 else f"Custom ({visual_fx})"
        lines.append(format_status_line("Visual effects", visual_fx_value, visual_fx == 2))

    thumbnails = query_registry_dword(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "IconsOnly",
        cancel_requested,
    )
    if thumbnails is None:
        lines.append(format_status_line("Thumbnail previews", "Unable to query", False))
    else:
        lines.append(format_status_line("Thumbnail previews", "Enabled" if thumbnails == 0 else "Disabled", thumbnails == 0))

    toast_enabled = query_registry_dword(
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
        "ToastEnabled",
        cancel_requested,
    )
    if toast_enabled is None:
        lines.append(format_status_line("Toast notifications", "Unable to query", False))
    else:
        lines.append(format_status_line("Toast notifications", "Disabled" if toast_enabled == 0 else "Enabled", toast_enabled == 0))

    notification_center = query_registry_dword(
        "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
        "DisableNotificationCenter",
        cancel_requested,
    )
    if notification_center is None:
        lines.append(format_status_line("Notification Center", "Unable to query", False))
    else:
        lines.append(
            format_status_line(
                "Notification Center",
                "Disabled" if notification_center == 1 else "Enabled",
                notification_center == 1,
            )
        )

    password_required = query_password_required_status(cancel_requested)
    if password_required is None:
        lines.append(format_status_line("Windows password", "Unable to query", False))
    else:
        lines.append(
            format_status_line(
                "Windows password",
                "Protected" if password_required else "Not protected",
                password_required,
            )
        )

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
        self.log_line.emit("")

        if self._cancelled():
            self.completed.emit(False, "cancelled")
            return

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
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.save_report_button = QtWidgets.QPushButton("Save Report (TXT)")

        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)

        self.apply_tasks = self._build_tasks()
        self.task_checkboxes: dict[str, QtWidgets.QCheckBox] = {}
        self.install_apps = self._build_install_apps()
        self.app_checkboxes: dict[str, QtWidgets.QCheckBox] = {}
        self.rename_input = QtWidgets.QLineEdit()
        self.rename_input.setPlaceholderText("New computer name")
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

        layout.addLayout(left_column, stretch=3)
        layout.addWidget(self.apps_group, stretch=1)

        self.select_all_checkbox.stateChanged.connect(self._toggle_all)
        self.inspect_button.clicked.connect(self._run_inspect)
        self.run_button.clicked.connect(self._run_apply)
        self.clear_button.clicked.connect(self.output.clear)
        self.cancel_button.clicked.connect(self._request_cancel)
        self.save_report_button.clicked.connect(self._save_report_txt)

        self._worker_thread: QtCore.QThread | None = None
        self._worker: SetupWorker | None = None

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

    def _build_tasks(self) -> list[ApplyTask]:
        return [
            ApplyTask(
                key="power_plan",
                label="Set power plan to High performance",
                action=lambda: [["powercfg", "/setactive", "SCHEME_MIN"]],
            ),
            ApplyTask(
                key="power_timeouts",
                label="Configure timeouts (Sleep/Hibernate/Disk=Never, Monitor=30m)",
                action=lambda: [
                    ["powercfg", "/hibernate", "off"],
                    ["powercfg", "/change", "standby-timeout-ac", "0"],
                    ["powercfg", "/change", "standby-timeout-dc", "0"],
                    ["powercfg", "/change", "hibernate-timeout-ac", "0"],
                    ["powercfg", "/change", "hibernate-timeout-dc", "0"],
                    ["powercfg", "/change", "disk-timeout-ac", "0"],
                    ["powercfg", "/change", "disk-timeout-dc", "0"],
                    ["powercfg", "/change", "monitor-timeout-ac", "30"],
                    ["powercfg", "/change", "monitor-timeout-dc", "30"],
                ],
            ),
            ApplyTask(
                key="usb_suspend",
                label="Disable USB selective suspend (AC/DC)",
                action=lambda: [
                    ["powercfg", "/setacvalueindex", "SCHEME_MIN", "2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "0"],
                    ["powercfg", "/setdcvalueindex", "SCHEME_MIN", "2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "0"],
                    ["powercfg", "/setactive", "SCHEME_MIN"],
                ],
            ),
            ApplyTask(
                key="fast_startup",
                label="Disable Fast Startup",
                action=lambda: [
                    ["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", "/v", "HiberbootEnabled", "/t", "REG_DWORD", "/d", "0", "/f"]
                ],
            ),
            ApplyTask(
                key="game_dvr",
                label="Disable Game Bar / Game DVR",
                action=lambda: [
                    ["reg", "add", "HKCU\\System\\GameConfigStore", "/v", "GameDVR_Enabled", "/t", "REG_DWORD", "/d", "0", "/f"],
                    ["reg", "add", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR", "/v", "AppCaptureEnabled", "/t", "REG_DWORD", "/d", "0", "/f"],
                    ["reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR", "/v", "AllowGameDVR", "/t", "REG_DWORD", "/d", "0", "/f"],
                ],
            ),
            ApplyTask(
                key="visual_effects",
                label="Set visual effects (best performance, keep thumbnails)",
                action=lambda: [
                    ["reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects", "/v", "VisualFXSetting", "/t", "REG_DWORD", "/d", "2", "/f"],
                    ["reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "/v", "IconsOnly", "/t", "REG_DWORD", "/d", "0", "/f"],
                ],
            ),
            ApplyTask(
                key="notifications",
                label="Disable Windows notifications (current user)",
                action=lambda: [
                    ["reg", "add", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications", "/v", "ToastEnabled", "/t", "REG_DWORD", "/d", "0", "/f"],
                    ["reg", "add", "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer", "/v", "DisableNotificationCenter", "/t", "REG_DWORD", "/d", "1", "/f"],
                ],
            ),
            ApplyTask(
                key="rename_pc",
                label="Rename computer",
                action=self._rename_computer_action,
            ),
        ]

    def _build_install_apps(self) -> list[InstallApp]:
        return [

            InstallApp("chrome", "Google Chrome", "Google.Chrome", "Utilities for creators"),
            InstallApp("davinci_resolve", "DaVinci Resolve", "BlackmagicDesign.DaVinciResolve", "Core video editing / post"),
            InstallApp("shotcut", "Shotcut", "Meltytech.Shotcut", "Core video editing / post"),
            InstallApp("kdenlive", "Kdenlive", "KDE.Kdenlive", "Core video editing / post"),
            InstallApp("handbrake", "HandBrake", "HandBrake.HandBrake", "Core video editing / post"),
            InstallApp("avidemux", "Avidemux", "Avidemux.Avidemux", "Core video editing / post"),
            InstallApp("obs", "OBS Studio", "OBSProject.OBSStudio", "Capture / streaming / recording"),
            InstallApp("sharex", "ShareX", "ShareX.ShareX", "Capture / streaming / recording"),
            InstallApp("audacity", "Audacity", "Audacity.Audacity", "Audio for video"),
            InstallApp("reaper", "REAPER", "Cockos.REAPER", "Audio for video"),
            InstallApp("vlc", "VLC media player", "VideoLAN.VLC", "Codecs / media tools"),
            InstallApp("ffmpeg", "FFmpeg", "Gyan.FFmpeg", "Codecs / media tools"),
            InstallApp("mediainfo", "MediaInfo", "MediaArea.MediaInfo.GUI", "Codecs / media tools"),
            InstallApp("mkvtoolnix", "MKVToolNix", "MoritzBunkus.MKVToolNix", "Codecs / media tools"),
            InstallApp("blender", "Blender", "BlenderFoundation.Blender", "Motion graphics / VFX / 3D"),
            InstallApp("natron", "Natron", "Natron.Natron", "Motion graphics / VFX / 3D"),
            InstallApp("notepadpp", "Notepad++", "Notepad++.Notepad++", "Utilities for creators"),
            InstallApp("seven_zip", "7-Zip", "7zip.7zip", "Utilities for creators"),
            InstallApp("everything", "Everything", "voidtools.Everything", "Utilities for creators"),
            InstallApp("crystaldiskinfo", "CrystalDiskInfo", "CrystalDewWorld.CrystalDiskInfo", "Utilities for creators"),
            InstallApp("hwinfo", "HWInfo", "REALiX.HWiNFO", "Utilities for creators"),
        ]

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
        self.save_report_button.setEnabled(not running)

    def _start_worker(self, worker: SetupWorker) -> None:
        self._worker_thread = QtCore.QThread(self)
        self._worker = worker
        self._worker.moveToThread(self._worker_thread)

        worker.log_line.connect(self._append)
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
