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
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence

from PyQt5 import QtCore, QtGui, QtWidgets


APP_VERSION = "0.1.2"
APP_EXE_NAME = f"PcCfg-v{APP_VERSION}"
APP_NAME = f"DXM - PC Setup v{APP_VERSION} (PyQt)"
APP_ICON_NAME = "PCSetup.ico"
APP_ICON_PATH = Path(__file__).resolve().parent / "Icon" / APP_ICON_NAME
APP_ID = "DXM.PCSetup"
CHECKLIST_WRAP_LINE_LEN = 64
STATUS_CHIP_STATES = ("PASS", "FAIL", "PENDING", "RUNNING", "NA")
MANUAL_STATUS_CYCLE = ("PENDING", "PASS", "FAIL", "NA")

from pccfg.domain.apply_catalog import APPLY_TASK_DEFINITIONS
from pccfg.domain.catalogs import INSTALL_APPS, MANUAL_INSTALL_APPS, validate_install_app_catalog
from pccfg.domain.checklist import (
    CHECKLIST_FIELDS,
    CHECKLIST_LOG_FILE,
    CHECKLIST_PROFILE_DIR,
    DEFAULT_PROFILE_FILE,
    COMPUTER_ROLE_OPTIONS,
    CHECKLIST_TASK_MAX_LEN,
    TECHNICIAN_DEFAULT_OPTIONS,
    FIELD_IDS_BY_LABEL,
    ITEM_IDS_BY_LABEL,
    ITEM_LABELS_BY_ID,
    SECTIONS,
)
from pccfg.domain.models import ApplyTask, ExecutionStep, InstallApp, ManualInstallApp
from pccfg.services.checklist_store import load_checklist_state, save_checklist_state
from pccfg.domain.hostname import build_hostname_value, normalize_numbering_value, to_pascal_case_alnum
from pccfg.services.checklist_sync import sync_inspect_status, sync_item_state_from_info_value
from pccfg.services.command_runner import (
    COMMAND_CANCEL_EXIT_CODE,
    COMMAND_TIMEOUT_EXIT_CODE,
    DEFAULT_APPLY_TIMEOUT_SEC,
    DEFAULT_INSPECT_TIMEOUT_SEC,
    DEFAULT_INSTALL_TIMEOUT_SEC,
    format_command,
    run_command_with_options,
)
from pccfg.services.system_probes import (
    detect_internet_reachability,
    detect_remote_desktop_readiness,
    detect_ssh_readiness,
    detect_unused_disks,
    detect_wifi_adapter,
    detect_wifi_connection,
)
from pccfg.services.winget import is_noop_install_success

CLIENT_NAME_FIELD_ID = "client_name"
COMPUTER_ROLE_FIELD_ID = "computer_role"
NUMBERING_FIELD_ID = "numbering"
HOSTNAME_FIELD_ID = "hostname"
INVENTORY_ID_FIELD_ID = "inventory_id"
DATE_FIELD_ID = "date"
FILE_NAME_FIELD_ID = "file_name"
HIDDEN_CHECKLIST_FIELD_IDS = {HOSTNAME_FIELD_ID, DATE_FIELD_ID, FILE_NAME_FIELD_ID}
CHECKLIST_ITEM_ID_BY_INFO_FIELD_ID = {
    CLIENT_NAME_FIELD_ID: CLIENT_NAME_FIELD_ID,
    COMPUTER_ROLE_FIELD_ID: COMPUTER_ROLE_FIELD_ID,
    NUMBERING_FIELD_ID: NUMBERING_FIELD_ID,
    INVENTORY_ID_FIELD_ID: INVENTORY_ID_FIELD_ID,
    "technician": "technician",
    "installed_cards": "installed_cards",
    "screenconnect_id": "record_scid",
}

DEFAULT_NA_ITEM_IDS = {INVENTORY_ID_FIELD_ID}
COMPUTER_ROLE_FIELD_CHOICES = ("", *COMPUTER_ROLE_OPTIONS)

INSTALLED_CARD_OPTIONS: tuple[str, ...] = (
    "Blackmagic DeckLink",
    "Blackmagic UltraStudio",
    "AJA Video Card",
    "10GbE NIC",
    "25GbE NIC",
    "RAID Controller",
    "USB Expansion Card",
    "Thunderbolt Expansion Card",
    "SAS HBA Controller",
    "Fiber Channel HBA",
    "SDI I/O Card",
    "Other",
)


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


def set_windows_app_user_model_id(app_id: str) -> None:
    """Set an explicit Windows AppUserModelID so taskbar/start icon uses app branding."""
    if not is_windows():
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception:
        # Icon setup should never prevent the app from launching.
        pass


def hide_windows_console() -> None:
    """Hide the attached Windows console window, if one exists."""
    if not is_windows():
        return
    try:
        console_window = ctypes.windll.kernel32.GetConsoleWindow()
        if console_window:
            ctypes.windll.user32.ShowWindow(console_window, 0)
    except Exception:
        # Console visibility should never block app startup.
        pass


def show_windows_console() -> bool:
    """Show (or create) a Windows console window for live command output."""
    if not is_windows():
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        console_window = kernel32.GetConsoleWindow()
        if not console_window:
            if not kernel32.AllocConsole():
                return False
            console_window = kernel32.GetConsoleWindow()
            if not console_window:
                return False

            sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="ignore")
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="ignore", buffering=1)
            sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="ignore", buffering=1)

        user32.ShowWindow(console_window, 5)
        return True
    except Exception:
        # Console visibility should never block app behavior.
        return False


def load_app_icon() -> QtGui.QIcon:
    """Load the app icon from ./Icon/PCSetup.ico if available."""
    if APP_ICON_PATH.exists():
        return QtGui.QIcon(str(APP_ICON_PATH))
    return QtGui.QIcon()


def load_stylesheet() -> str:
    """Load optional Qt stylesheet from ./style/app.qss."""
    style_dir = Path(__file__).resolve().parent / "style"
    stylesheet_path = style_dir / "app.qss"
    if not stylesheet_path.exists():
        return ""

    stylesheet = stylesheet_path.read_text(encoding="utf-8")
    for svg_name in ("arrow_down_light.svg", "arrow_down_disabled.svg"):
        svg_path = (style_dir / svg_name).resolve()
        if svg_path.exists():
            # Qt stylesheet `url(...)` handling on Windows can mis-handle `file:///...`
            # URIs (it may prepend the current working directory and treat them as
            # relative). Use a normalized absolute local path instead.
            svg_qss_path = svg_path.as_posix()
            stylesheet = stylesheet.replace(
                f"url(style/{svg_name})",
                f'url("{svg_qss_path}")',
            )
    return stylesheet


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


def _command_shell_kind(command: Sequence[str]) -> str:
    """Classify command as cmd or powershell for copy helpers."""
    if not command:
        return "cmd"
    executable = command[0].strip().lower()
    return "powershell" if executable in {"powershell", "pwsh"} else "cmd"


def _extract_powershell_snippet(command: Sequence[str]) -> str:
    """Return the inner PowerShell script when using -Command wrappers."""
    if not command:
        return ""

    lowered = [part.lower() for part in command]
    for arg_name in ("-command", "-c"):
        if arg_name not in lowered:
            continue
        command_index = lowered.index(arg_name)
        if command_index + 1 < len(command):
            return command[command_index + 1]
    return format_command(list(command))


class DragCheckTreeWidget(QtWidgets.QTreeWidget):
    """QTreeWidget that supports click-and-drag checkbox toggling for task rows."""

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._drag_check_active = False
        self._drag_check_state = QtCore.Qt.Checked
        self._drag_check_last_item: QtWidgets.QTreeWidgetItem | None = None

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        if event.button() == QtCore.Qt.LeftButton:
            item = self.itemAt(event.pos())
            clicked_column = self.columnAt(event.pos().x())
            if item is not None and clicked_column == 0 and self._is_task_item(item):
                self.clearSelection()
                self.setCurrentItem(None)
                self._drag_check_active = True
                self._drag_check_state = (
                    QtCore.Qt.Unchecked if item.checkState(0) == QtCore.Qt.Checked else QtCore.Qt.Checked
                )
                self._drag_check_last_item = None
                self._apply_drag_check(item)
                event.accept()
                return

        self._drag_check_active = False
        self._drag_check_last_item = None
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QtGui.QMouseEvent) -> None:
        if self._drag_check_active and (event.buttons() & QtCore.Qt.LeftButton):
            item = self.itemAt(event.pos())
            if item is not None and item is not self._drag_check_last_item and self._is_task_item(item):
                self._apply_drag_check(item)
                event.accept()
                return

        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QtGui.QMouseEvent) -> None:
        if event.button() == QtCore.Qt.LeftButton:
            self._drag_check_active = False
            self._drag_check_last_item = None
        super().mouseReleaseEvent(event)

    def _apply_drag_check(self, item: QtWidgets.QTreeWidgetItem) -> None:
        item.setCheckState(0, self._drag_check_state)
        self._drag_check_last_item = item

    @staticmethod
    def _is_task_item(item: QtWidgets.QTreeWidgetItem) -> bool:
        task_id = item.data(0, QtCore.Qt.UserRole)
        return isinstance(task_id, str) and bool(task_id)


class DragCheckBox(QtWidgets.QCheckBox):
    """App checkbox class (drag behavior is provided by :class:`DragCheckBoxEventFilter`)."""


class DragCheckBoxEventFilter(QtCore.QObject):
    """Enable click-and-drag checkbox toggling for every checkbox widget in the UI."""

    def __init__(self, parent: QtCore.QObject | None = None) -> None:
        super().__init__(parent)
        self._drag_active = False
        self._drag_state = False
        self._drag_hover_checkbox: DragCheckBox | None = None

    def eventFilter(self, watched: QtCore.QObject, event: QtCore.QEvent) -> bool:
        self._stop_drag_if_released()

        if self._drag_active and event.type() == QtCore.QEvent.MouseMove:
            if QtWidgets.QApplication.mouseButtons() & QtCore.Qt.LeftButton:
                self._apply_drag_to_cursor_checkbox()

        if isinstance(watched, DragCheckBox):
            if event.type() == QtCore.QEvent.MouseButtonPress:
                mouse_event = event if isinstance(event, QtGui.QMouseEvent) else None
                if mouse_event and mouse_event.button() == QtCore.Qt.LeftButton:
                    self._drag_active = True
                    self._drag_state = not watched.isChecked()
                    watched.setChecked(self._drag_state)
                    self._drag_hover_checkbox = watched
                    event.accept()
                    return True

            if event.type() == QtCore.QEvent.MouseButtonRelease:
                mouse_event = event if isinstance(event, QtGui.QMouseEvent) else None
                if mouse_event and mouse_event.button() == QtCore.Qt.LeftButton and self._drag_active:
                    self._stop_drag()
                    event.accept()
                    return True

        elif self._drag_active and event.type() == QtCore.QEvent.MouseButtonRelease:
            mouse_event = event if isinstance(event, QtGui.QMouseEvent) else None
            if mouse_event and mouse_event.button() == QtCore.Qt.LeftButton:
                self._stop_drag()

        return super().eventFilter(watched, event)

    def _stop_drag_if_released(self) -> None:
        if self._drag_active and not (QtWidgets.QApplication.mouseButtons() & QtCore.Qt.LeftButton):
            self._stop_drag()

    def _stop_drag(self) -> None:
        self._drag_active = False
        self._drag_hover_checkbox = None

    def _apply_drag_to_cursor_checkbox(self) -> None:
        checkbox = self._drag_checkbox_at_cursor()
        if checkbox is None:
            self._drag_hover_checkbox = None
            return
        if checkbox is self._drag_hover_checkbox:
            return
        checkbox.setChecked(self._drag_state)
        self._drag_hover_checkbox = checkbox

    def _drag_checkbox_at_cursor(self) -> DragCheckBox | None:
        widget = QtWidgets.QApplication.widgetAt(QtGui.QCursor.pos())
        while widget is not None:
            if isinstance(widget, DragCheckBox):
                return widget
            widget = widget.parentWidget()
        return None


def _clean_short_hardware_value(value: str) -> str:
    """Normalize long hardware descriptors to compact report values."""
    normalized = re.sub(r"\(R\)|\(TM\)|\(C\)", "", value, flags=re.IGNORECASE)
    normalized = re.sub(r"\s+", " ", normalized).strip(" -")
    return normalized


def short_cpu_value(cpu_name: str) -> str:
    """Extract compact CPU text (for example: Intel i7-12700)."""
    cleaned = _clean_short_hardware_value(cpu_name)
    intel_match = re.search(r"(Intel).*?\b(i[3579]-\d{4,5}[A-Z]?)\b", cleaned, flags=re.IGNORECASE)
    if intel_match:
        return f"Intel {intel_match.group(2).upper()}"

    amd_match = re.search(r"(AMD).*?\b(Ryzen\s+[3579]\s+\d{3,5}[A-Z0-9]*)\b", cleaned, flags=re.IGNORECASE)
    if amd_match:
        return f"AMD {amd_match.group(2)}"
    return cleaned


def detect_system_info(cancel_requested: Callable[[], bool] | None = None) -> dict[str, str]:
    """Collect CPU/board/BIOS and IP details for active physical adapters."""
    command = (
        "$cpu = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name); "
        "$board = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "$bios = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty SMBIOSBIOSVersion); "
        "$adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }; "
        "$ipRows = @(); "
        "foreach ($adapter in $adapters) { "
        "  $ips = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | "
        "    Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -and $_.IPAddress -notlike 'fe80*' }; "
        "  $ipv4 = @($ips | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -ExpandProperty IPAddress); "
        "  $ipv6 = @($ips | Where-Object { $_.AddressFamily -eq 'IPv6' } | Select-Object -ExpandProperty IPAddress); "
        "  $ipRows += [PSCustomObject]@{ Adapter = $adapter.Name; IPv4 = $ipv4; IPv6 = $ipv6 }; "
        "}; "
        "[PSCustomObject]@{ "
        "  CPU = $cpu; "
        "  Motherboard = ((@($board.Manufacturer, $board.Product) | Where-Object { $_ }) -join ' '); "
        "  BIOS = $bios; "
        "  IP = $ipRows "
        "} | ConvertTo-Json -Compress -Depth 4"
    )
    rc, output = run_command_with_options(
        ["powershell", "-NoProfile", "-Command", command],
        timeout_sec=DEFAULT_INSPECT_TIMEOUT_SEC,
        cancel_requested=cancel_requested,
    )
    if rc != 0:
        return {
            "cpu": "Unable to query",
            "motherboard": "Unable to query",
            "bios": "Unable to query",
            "ip": "Unable to query",
        }

    payload = parse_json_payload(output)
    row = payload[0] if payload else {}
    cpu_value = short_cpu_value(str(row.get("CPU", "")).strip()) if row.get("CPU") else "Unknown"
    motherboard = _clean_short_hardware_value(str(row.get("Motherboard", "")).strip()) or "Unknown"
    bios = _clean_short_hardware_value(str(row.get("BIOS", "")).strip()) or "Unknown"

    ip_rows = row.get("IP")
    ip_parts: list[str] = []
    if isinstance(ip_rows, dict):
        ip_rows = [ip_rows]
    if isinstance(ip_rows, list):
        for ip_row in ip_rows:
            if not isinstance(ip_row, dict):
                continue
            adapter = str(ip_row.get("Adapter", "Adapter")).strip() or "Adapter"
            ipv4_values = ip_row.get("IPv4")
            ipv6_values = ip_row.get("IPv6")

            ipv4_list = [str(ipv4_values).strip()] if isinstance(ipv4_values, str) else [str(v).strip() for v in ipv4_values or [] if str(v).strip()]
            ipv6_list = [str(ipv6_values).strip()] if isinstance(ipv6_values, str) else [str(v).strip() for v in ipv6_values or [] if str(v).strip()]

            if not ipv4_list and not ipv6_list:
                continue
            ip_parts.append(f"{adapter}: IPv4={', '.join(ipv4_list) if ipv4_list else '-'}, IPv6={', '.join(ipv6_list) if ipv6_list else '-'}")

    return {
        "cpu": cpu_value,
        "motherboard": motherboard,
        "bios": bios,
        "ip": " | ".join(ip_parts) if ip_parts else "No IP address on active physical adapters",
    }


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

    def _emit_command_progress(self, line: str) -> None:
        if line.strip():
            self.log_line.emit(f"    {line}")

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

        self.step_started.emit("System information")
        self.log_line.emit("System information")
        self.log_line.emit("-" * 60)
        system_info = detect_system_info(self._cancelled)
        self.log_line.emit(format_kv_line("CPU", system_info["cpu"], width=12))
        self.log_line.emit(format_kv_line("Motherboard", system_info["motherboard"], width=12))
        self.log_line.emit(format_kv_line("BIOS", system_info["bios"], width=12))
        self.log_line.emit(format_kv_line("IP", system_info["ip"], width=12))
        self.log_line.emit("")
        self.step_finished.emit("System information", True)

        if self._cancelled():
            self.completed.emit(False, "cancelled")
            return

        inspect_checks = {
            "Install network drivers (LAN/10GbE/Wi-Fi)": "RUNNING",
            "Test Wi-Fi": "RUNNING",
            "Internet reachable": "RUNNING",
            "Ensure all disks are visible": "RUNNING",
            "Validate SSH (installed + running + listening:22)": "RUNNING",
            "Enable Remote Desktop (service + firewall + NLA)": "RUNNING",
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
        disk_ok, disk_detail = detect_unused_disks(self._cancelled)
        ssh_ok, ssh_detail = detect_ssh_readiness(self._cancelled)
        rdp_ok, rdp_detail = detect_remote_desktop_readiness(self._cancelled)

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
            self.checklist_status.emit("Internet reachable", "PENDING", False, internet_detail)
        else:
            self.log_line.emit(format_status_line("Internet", internet_detail, internet_ok))
            self.checklist_status.emit(
                "Internet reachable",
                "PASS" if internet_ok else "FAIL",
                internet_ok,
                internet_detail,
            )

        if disk_ok is None:
            self.log_line.emit(format_status_line("Disk usage", disk_detail, False))
            self.checklist_status.emit("Ensure all disks are visible", "PENDING", False, disk_detail)
        else:
            self.log_line.emit(format_status_line("Disk usage", disk_detail, disk_ok))
            self.checklist_status.emit("Ensure all disks are visible", "PASS" if disk_ok else "FAIL", disk_ok, disk_detail)

        if ssh_ok is None:
            self.log_line.emit(format_status_line("SSH readiness", ssh_detail, False))
            self.checklist_status.emit("Validate SSH (installed + running + listening:22)", "PENDING", False, ssh_detail)
        else:
            self.log_line.emit(format_status_line("SSH readiness", ssh_detail, ssh_ok))
            self.checklist_status.emit(
                "Validate SSH (installed + running + listening:22)",
                "PASS" if ssh_ok else "FAIL",
                ssh_ok,
                ssh_detail,
            )

        if rdp_ok is None:
            self.log_line.emit(format_status_line("Remote Desktop", rdp_detail, False))
            self.checklist_status.emit("Enable Remote Desktop (service + firewall + NLA)", "PENDING", False, rdp_detail)
        else:
            self.log_line.emit(format_status_line("Remote Desktop", rdp_detail, rdp_ok))
            self.checklist_status.emit(
                "Enable Remote Desktop (service + firewall + NLA)",
                "PASS" if rdp_ok else "FAIL",
                rdp_ok,
                rdp_detail,
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

        apply_task_map = {
            "Automate Windows Update scan/download/install": "Run Windows Update until \"Up to date\"",
            "Install/enable OpenSSH Server + firewall": "Validate SSH (installed + running + listening:22)",
            "Enable Remote Desktop (service + firewall + NLA)": "Enable Remote Desktop (service + firewall + NLA)",
        }
        for idx, step in enumerate(self._apply_steps, start=1):
            if self._cancelled():
                self.completed.emit(False, "cancelled")
                return

            step_name = f"[{idx}/{len(self._apply_steps)}] {step.label}"
            self.step_started.emit(step_name)
            self.log_line.emit(step_name)
            ok = True
            for cmd in step.commands:
                self.log_line.emit(f"  $ {format_command(cmd)}")
                rc, out = run_command_with_options(
                    cmd,
                    timeout_sec=DEFAULT_APPLY_TIMEOUT_SEC,
                    cancel_requested=self._cancelled,
                    on_output=self._emit_command_progress,
                )
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
            mapped_task = apply_task_map.get(step.label)
            if mapped_task:
                self.checklist_status.emit(mapped_task, "PASS" if ok else "FAIL", ok, f"Apply: {step.label}")

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
                self.log_line.emit(f"  $ {format_command(cmd)}")
                rc, out = run_command_with_options(
                    cmd,
                    timeout_sec=DEFAULT_INSTALL_TIMEOUT_SEC,
                    cancel_requested=self._cancelled,
                    on_output=self._emit_command_progress,
                )
                if rc == COMMAND_CANCEL_EXIT_CODE:
                    self.log_line.emit("    -> CANCELLED")
                    self.step_finished.emit(step_name, False)
                    self.completed.emit(False, "cancelled")
                    return
                if rc == COMMAND_TIMEOUT_EXIT_CODE:
                    self.log_line.emit(f"    -> FAIL (timeout after {DEFAULT_INSTALL_TIMEOUT_SEC}s)")
                    self.step_finished.emit(step_name, False)
                    self.checklist_status.emit(step.label, "FAIL", False, "Apply: winget install timeout")
                else:
                    install_ok = rc == 0 or is_noop_install_success(out)
                    status = "OK" if install_ok else f"FAIL (exit {rc})"
                    self.log_line.emit(f"    -> {status}")
                    self.step_finished.emit(step_name, install_ok)
                    self.checklist_status.emit(step.label, "PASS" if install_ok else "FAIL", install_ok, "Apply: winget install")
                if out:
                    self.log_line.emit(f"    {out}")
                self.log_line.emit("")

        self.log_line.emit("DONE. Reboot is recommended (required if computer rename was applied).")
        self.completed.emit(True, "done")


class InstalledCardsInput(QtWidgets.QWidget):
    changed = QtCore.pyqtSignal()

    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.choices = QtWidgets.QComboBox()
        self.choices.addItems(INSTALLED_CARD_OPTIONS)
        self.add_selected_button = QtWidgets.QPushButton("Add")
        self.manual_input = QtWidgets.QLineEdit()
        self.manual_input.setPlaceholderText("Manual card name")
        self.add_manual_button = QtWidgets.QPushButton("Add manual")
        self.items = QtWidgets.QListWidget()
        self.items.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.remove_button = QtWidgets.QPushButton("Remove selected")

        root = QtWidgets.QVBoxLayout(self)
        pick_row = QtWidgets.QHBoxLayout()
        pick_row.addWidget(self.choices, stretch=1)
        pick_row.addWidget(self.add_selected_button)

        manual_row = QtWidgets.QHBoxLayout()
        manual_row.addWidget(self.manual_input, stretch=1)
        manual_row.addWidget(self.add_manual_button)

        root.addLayout(pick_row)
        root.addLayout(manual_row)
        root.addWidget(self.items)
        root.addWidget(self.remove_button)

        self.add_selected_button.clicked.connect(lambda: self._add_value(self.choices.currentText()))
        self.add_manual_button.clicked.connect(lambda: self._add_value(self.manual_input.text()))
        self.manual_input.returnPressed.connect(lambda: self._add_value(self.manual_input.text()))
        self.remove_button.clicked.connect(self._remove_selected)

    def values(self) -> list[str]:
        return [self.items.item(index).text() for index in range(self.items.count())]

    def text_value(self) -> str:
        return ", ".join(self.values())

    def set_values_from_text(self, value: str) -> None:
        self.items.clear()
        if not value:
            return
        for raw_part in re.split(r"[,;\n]+", value):
            part = raw_part.strip()
            if part:
                self._add_value(part, emit_signal=False)

    def _add_value(self, value: str, emit_signal: bool = True) -> None:
        candidate = value.strip()
        if not candidate:
            return

        for existing in self.values():
            if existing.casefold() == candidate.casefold():
                self.manual_input.clear()
                return

        self.items.addItem(candidate)
        self.manual_input.clear()
        if emit_signal:
            self.changed.emit()

    def _remove_selected(self) -> None:
        row = self.items.currentRow()
        if row < 0:
            return
        self.items.takeItem(row)
        self.changed.emit()


class StatusChipLabel(QtWidgets.QLabel):
    clicked = QtCore.pyqtSignal()

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        if event.button() == QtCore.Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class MainWindow(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._mirror_output_to_external_console = False
        self._external_console_visible = False
        self._drag_checkbox_filter = DragCheckBoxEventFilter(self)
        app = QtWidgets.QApplication.instance()
        if app is not None:
            app.installEventFilter(self._drag_checkbox_filter)
        self.setWindowTitle(APP_NAME)
        icon = load_app_icon()
        if not icon.isNull():
            self.setWindowIcon(icon)
        self.resize(920, 700)

        self.select_all_checkbox = DragCheckBox("Select all APPLY options")
        self.select_all_checkbox.setChecked(False)

        self.inspect_button = QtWidgets.QPushButton("Inspect")
        self.run_button = QtWidgets.QPushButton("Run")
        self.clear_button = QtWidgets.QPushButton("Clear Output")
        self.new_install_button = QtWidgets.QPushButton("New install")
        self.export_installation_report_button = QtWidgets.QPushButton("Export installation report")
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.save_report_button = QtWidgets.QPushButton("Save Report (TXT)")
        self.external_console_button = QtWidgets.QPushButton("Show external console")

        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)

        self.apply_tasks = self._build_tasks()
        self.task_checkboxes: dict[str, QtWidgets.QCheckBox] = {}
        self._task_command_sources: dict[str, Callable[[], list[list[str]]]] = {
            task.key: task.action for task in self.apply_tasks
        }
        self.install_apps = self._build_install_apps()
        self.manual_install_apps = self._build_manual_install_apps()
        self.app_checkboxes: dict[str, QtWidgets.QCheckBox] = {}
        self._app_by_key: dict[str, InstallApp] = {app.key: app for app in self.install_apps}
        self.rename_input = QtWidgets.QLineEdit()
        self.rename_input.setPlaceholderText("Auto-generated from checklist hostname")
        self.rename_input.setReadOnly(True)
        self.rename_input.setEnabled(False)

        self.tasks_group = QtWidgets.QGroupBox("APPLY Options")
        self.tasks_layout = QtWidgets.QVBoxLayout(self.tasks_group)
        for task in self.apply_tasks:
            cb = DragCheckBox(task.label)
            cb.setChecked(False)
            self.task_checkboxes[task.key] = cb
            cb.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
            cb.customContextMenuRequested.connect(
                lambda pos, task_key=task.key, checkbox=cb: self._show_copy_code_context_menu(checkbox, pos, task_key=task_key)
            )
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
            cb = DragCheckBox(app.label)
            cb.setChecked(False)
            self.app_checkboxes[app.key] = cb
            cb.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
            cb.customContextMenuRequested.connect(
                lambda pos, app_key=app.key, checkbox=cb: self._show_copy_code_context_menu(checkbox, pos, app_key=app_key)
            )
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

        self.manual_layout.addWidget(QtWidgets.QLabel(""))
        info_title = QtWidgets.QLabel("Setup information")
        info_font = info_title.font()
        info_font.setBold(True)
        info_title.setFont(info_font)
        self.manual_layout.addWidget(info_title)
        self.manual_info_form = QtWidgets.QVBoxLayout()
        self.manual_layout.addLayout(self.manual_info_form)
        self.manual_layout.addStretch(1)

        self.installation_checklist_group = QtWidgets.QGroupBox("Installation PC checklist")
        checklist_group_layout = QtWidgets.QVBoxLayout(self.installation_checklist_group)

        self.installation_checklist_progress = QtWidgets.QLabel("0/0 completed")
        checklist_group_layout.addWidget(self.installation_checklist_progress)

        self.installation_checklist_tree = DragCheckTreeWidget()
        self.installation_checklist_tree.setObjectName("installationChecklistTree")
        self.installation_checklist_tree.setColumnCount(2)
        self.installation_checklist_tree.setHeaderLabels(["Task", "Status"])
        self.installation_checklist_tree.setRootIsDecorated(False)
        self.installation_checklist_tree.setMouseTracking(True)
        self.installation_checklist_tree.setAlternatingRowColors(True)
        self.installation_checklist_tree.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.installation_checklist_tree.setUniformRowHeights(False)
        self.installation_checklist_tree.setIndentation(0)
        self.installation_checklist_tree.setTextElideMode(QtCore.Qt.ElideNone)
        self.installation_checklist_tree.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self.installation_checklist_tree.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.installation_checklist_tree.header().setStretchLastSection(False)
        self.installation_checklist_tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        self.installation_checklist_tree.header().setSectionResizeMode(1, QtWidgets.QHeaderView.Fixed)
        self.installation_checklist_tree.setColumnWidth(1, 110)
        self.installation_checklist_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        checklist_group_layout.addWidget(self.installation_checklist_tree, stretch=1)

        self.checklist_status_bar = QtWidgets.QLabel("Ready")
        self.checklist_status_bar.setObjectName("checklistStatusBar")
        self.checklist_status_bar.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.checklist_status_bar.setMinimumHeight(24)
        self.checklist_status_bar.setWordWrap(False)
        checklist_group_layout.addWidget(self.checklist_status_bar)

        profile_row = QtWidgets.QHBoxLayout()
        self.profile_selector = QtWidgets.QComboBox()
        self.save_profile_button = QtWidgets.QPushButton("Save profile")
        self.reload_profile_button = QtWidgets.QPushButton("Reload profile")
        self.delete_profile_button = QtWidgets.QPushButton("Delete profile")
        profile_row.addWidget(QtWidgets.QLabel("Profile"))
        profile_row.addWidget(self.profile_selector, stretch=1)
        profile_row.addWidget(self.save_profile_button)
        profile_row.addWidget(self.reload_profile_button)
        profile_row.addWidget(self.delete_profile_button)
        checklist_group_layout.addLayout(profile_row)

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
        self.checklist_item_states: dict[str, str] = {}
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

                status_chip = StatusChipLabel("PENDING")
                status_chip.setObjectName("checklistStatusChip")
                status_chip.setProperty("chipStatus", "PENDING")
                status_chip.setAlignment(QtCore.Qt.AlignCenter)
                status_chip.clicked.connect(lambda task_id=section_item.item_id: self._on_status_chip_clicked(task_id))
                self.installation_checklist_tree.setItemWidget(checklist_item, 1, status_chip)
                self.checklist_status_chips[section_item.item_id] = status_chip
                self.checklist_runtime_status[section_item.item_id] = ("PENDING", "Waiting")
                self.checklist_item_states[section_item.item_id] = "UNCHECKED"

        info_fields = [field for field in CHECKLIST_FIELDS if field.field_id not in HIDDEN_CHECKLIST_FIELD_IDS]
        for field in info_fields:
            field_label = QtWidgets.QLabel(f"{field.label}:")
            field_label.setObjectName("setupInfoLabel")
            value_input = self._create_checklist_info_input(field)
            self.manual_info_form.addWidget(field_label)
            self.manual_info_form.addWidget(value_input)
            self.checklist_info_inputs[field.field_id] = value_input

        self.installation_checklist_tree.itemChanged.connect(self._on_installation_checklist_item_changed)
        self.installation_checklist_tree.currentItemChanged.connect(self._on_checklist_item_focus_changed)
        self.installation_checklist_tree.itemEntered.connect(self._on_checklist_item_hovered)
        self.installation_checklist_tree.customContextMenuRequested.connect(self._on_checklist_context_menu)
        self.installation_checklist_tree.resizeColumnToContents(1)
        self.installation_checklist_tree.setColumnWidth(1, 110)
        self._ensure_profile_storage()
        self._refresh_profile_selector()
        self._apply_default_checklist_states()
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
        bottom_row.addWidget(self.external_console_button)
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
        self.external_console_button.clicked.connect(self._toggle_external_console)
        self.save_report_button.clicked.connect(self._save_report_txt)
        self.save_profile_button.clicked.connect(self._save_profile)
        self.reload_profile_button.clicked.connect(self._reload_selected_profile)
        self.delete_profile_button.clicked.connect(self._delete_selected_profile)
        self.profile_selector.currentIndexChanged.connect(self._update_profile_action_buttons)

        self._worker_thread: QtCore.QThread | None = None
        self._worker: SetupWorker | None = None
        self._active_worker_mode: str = ""

        self._apply_checklist_autofill()

    def _on_installation_checklist_item_changed(self, _item: QtWidgets.QTreeWidgetItem | None = None, _column: int = 0) -> None:
        if _item is not None and _column == 0:
            task_id = _item.data(0, QtCore.Qt.UserRole)
            if isinstance(task_id, str) and task_id:
                if _item.checkState(0) == QtCore.Qt.Checked:
                    self.checklist_item_states[task_id] = "CHECKED"
                    self._set_checklist_item_status(task_id, "PASS", "Checked")
                elif self.checklist_item_states.get(task_id) != "NA" and self.checklist_runtime_status.get(task_id, ("", ""))[0] in {"PASS", "PENDING", "NA"}:
                    self.checklist_item_states[task_id] = "UNCHECKED"
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

    def _on_status_chip_clicked(self, task_id: str) -> None:
        item = self.checklist_item_by_id.get(task_id)
        if item is None:
            return

        current_status = self.checklist_runtime_status.get(task_id, ("PENDING", "Waiting"))[0]
        try:
            current_index = MANUAL_STATUS_CYCLE.index(current_status)
        except ValueError:
            current_index = 0
        next_status = MANUAL_STATUS_CYCLE[(current_index + 1) % len(MANUAL_STATUS_CYCLE)]

        if next_status == "PASS":
            self.checklist_item_states[task_id] = "CHECKED"
            item.setCheckState(0, QtCore.Qt.Checked)
            detail = "Marked complete"
        elif next_status == "NA":
            self.checklist_item_states[task_id] = "NA"
            item.setCheckState(0, QtCore.Qt.Unchecked)
            detail = "Not applicable"
        else:
            self.checklist_item_states[task_id] = "UNCHECKED"
            item.setCheckState(0, QtCore.Qt.Unchecked)
            detail = "Waiting" if next_status == "PENDING" else "Needs attention"

        self._set_checklist_item_status(task_id, next_status, detail)
        self._update_installation_checklist_progress()
        self._set_checklist_status_message(item)
        self._save_installation_checklist_state()

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

    def _on_checklist_context_menu(self, pos: QtCore.QPoint) -> None:
        selected_items = [
            item
            for item in self.installation_checklist_tree.selectedItems()
            if isinstance(item.data(0, QtCore.Qt.UserRole), str) and item.data(0, QtCore.Qt.UserRole)
        ]
        if not selected_items:
            item = self.installation_checklist_tree.itemAt(pos)
            if item is None:
                return
            task_id = item.data(0, QtCore.Qt.UserRole)
            if not isinstance(task_id, str) or not task_id:
                return
            selected_items = [item]

        selected_task_ids = [str(item.data(0, QtCore.Qt.UserRole)) for item in selected_items]
        if not selected_task_ids:
            return

        menu = QtWidgets.QMenu(self)
        mark_checked = menu.addAction(
            "Check selected task" if len(selected_task_ids) == 1 else f"Check {len(selected_task_ids)} selected tasks"
        )
        clear_checked = menu.addAction(
            "Uncheck selected task" if len(selected_task_ids) == 1 else f"Uncheck {len(selected_task_ids)} selected tasks"
        )
        menu.addSeparator()
        all_selected_na = all(self.checklist_item_states.get(task_id) == "NA" for task_id in selected_task_ids)
        toggle_na = menu.addAction("Clear Not Applicable" if all_selected_na else "Mark as Not Applicable")
        chosen = menu.exec_(self.installation_checklist_tree.viewport().mapToGlobal(pos))
        if chosen is None:
            return

        if chosen == mark_checked:
            for selected_item, task_id in zip(selected_items, selected_task_ids):
                self.checklist_item_states[task_id] = "CHECKED"
                selected_item.setCheckState(0, QtCore.Qt.Checked)
                self._set_checklist_item_status(task_id, "PASS", "Checked")
        elif chosen == clear_checked:
            for selected_item, task_id in zip(selected_items, selected_task_ids):
                if self.checklist_item_states.get(task_id) == "NA":
                    continue
                self.checklist_item_states[task_id] = "UNCHECKED"
                selected_item.setCheckState(0, QtCore.Qt.Unchecked)
                self._set_checklist_item_status(task_id, "PENDING", "Waiting")
        elif chosen == toggle_na:
            for selected_item, task_id in zip(selected_items, selected_task_ids):
                if all_selected_na:
                    self.checklist_item_states[task_id] = "UNCHECKED"
                    selected_item.setCheckState(0, QtCore.Qt.Unchecked)
                    self._set_checklist_item_status(task_id, "PENDING", "Waiting")
                else:
                    self.checklist_item_states[task_id] = "NA"
                    selected_item.setCheckState(0, QtCore.Qt.Unchecked)
                    self._set_checklist_item_status(task_id, "NA", "Not applicable")
        else:
            return

        self._update_installation_checklist_progress()
        self._save_installation_checklist_state()

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

        self._sync_checklist_item_from_info_field(field_id)

        self._save_installation_checklist_state()

    def _create_checklist_info_input(self, field) -> QtWidgets.QWidget:
        if field.field_id == COMPUTER_ROLE_FIELD_ID:
            value_input = QtWidgets.QComboBox()
            value_input.addItems(COMPUTER_ROLE_FIELD_CHOICES)
            value_input.currentTextChanged.connect(
                lambda _value, field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
            )
            return value_input

        if field.field_type == "date":
            value_input = QtWidgets.QDateEdit()
            value_input.setDisplayFormat("yyyy-MM-dd")
            value_input.setCalendarPopup(True)
            value_input.setDate(QtCore.QDate.currentDate())
            value_input.dateChanged.connect(
                lambda _value, field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
            )
            return value_input

        if field.field_type == "numbering":
            value_input = QtWidgets.QComboBox()
            value_input.addItems([f"{number:02d}" for number in range(1, 100)])
            value_input.setCurrentIndex(-1)
            value_input.currentTextChanged.connect(
                lambda _value, field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
            )
            return value_input

        if field.field_type == "technician":
            value_input = QtWidgets.QComboBox()
            value_input.setEditable(True)
            value_input.addItems(TECHNICIAN_DEFAULT_OPTIONS)
            value_input.currentTextChanged.connect(
                lambda _value, field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
            )
            value_input.lineEdit().editingFinished.connect(
                lambda input_widget=value_input: self._add_combo_value_if_missing(input_widget)
            )
            value_input.lineEdit().returnPressed.connect(
                lambda input_widget=value_input: self._add_combo_value_if_missing(input_widget)
            )
            return value_input

        if field.field_id == "installed_cards":
            value_input = InstalledCardsInput()
            value_input.changed.connect(
                lambda field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
            )
            return value_input

        value_input = QtWidgets.QLineEdit()
        value_input.setPlaceholderText("Add details")
        if field.field_id == HOSTNAME_FIELD_ID:
            value_input.setReadOnly(True)
            value_input.setPlaceholderText("Auto-generated")
        value_input.textChanged.connect(
            lambda _value, field_id=field.field_id: self._on_checklist_info_field_changed(field_id)
        )
        return value_input

    def _sync_checklist_item_from_info_field(self, field_id: str) -> None:
        task_id = CHECKLIST_ITEM_ID_BY_INFO_FIELD_ID.get(field_id)
        if not task_id:
            return

        item = self.checklist_item_by_id.get(task_id)
        if item is None:
            return

        value = self._get_checklist_field_value(field_id).strip()
        next_state, status, detail = sync_item_state_from_info_value(self.checklist_item_states.get(task_id), value)
        if next_state == "NA":
            return

        self.checklist_item_states[task_id] = next_state
        item.setCheckState(0, QtCore.Qt.Checked if next_state == "CHECKED" else QtCore.Qt.Unchecked)
        self._set_checklist_item_status(task_id, status, detail)

    def _apply_checklist_autofill(self) -> None:
        hostname_text = self._build_hostname_value()
        file_name_text = self._build_file_name_value()
        self._autofill_line_edit(HOSTNAME_FIELD_ID, hostname_text)
        self._autofill_line_edit(FILE_NAME_FIELD_ID, file_name_text)
        self.rename_input.setText(hostname_text)
        for field_id in CHECKLIST_ITEM_ID_BY_INFO_FIELD_ID:
            self._sync_checklist_item_from_info_field(field_id)

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

        next_state, set_checked = sync_inspect_status(self.checklist_item_states.get(task_id), task_id, status, should_check)
        if next_state is None:
            return

        self.checklist_item_states[task_id] = next_state
        self._set_checklist_item_status(task_id, status, detail)
        if set_checked:
            item.setCheckState(0, QtCore.Qt.Checked)
        elif status in {"FAIL", "PENDING"} and item.checkState(0) != QtCore.Qt.Checked:
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
        return build_hostname_value(
            self._get_checklist_info_text(CLIENT_NAME_FIELD_ID),
            self._get_checklist_info_text(COMPUTER_ROLE_FIELD_ID),
            self._get_checklist_info_text(NUMBERING_FIELD_ID),
        )

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
        if isinstance(widget, InstalledCardsInput):
            return widget.text_value().strip()
        if isinstance(widget, QtWidgets.QLineEdit):
            return widget.text().strip()
        if isinstance(widget, QtWidgets.QComboBox):
            return widget.currentText().strip()
        return ""

    def _update_installation_checklist_progress(self) -> None:
        applicable_items = [
            item for item in self.installation_checklist_items
            if self.checklist_item_states.get(str(item.data(0, QtCore.Qt.UserRole))) != "NA"
        ]
        total = len(applicable_items)
        done = sum(item.checkState(0) == QtCore.Qt.Checked for item in applicable_items)
        skipped = sum(self.checklist_item_states.get(str(item.data(0, QtCore.Qt.UserRole))) == "NA" for item in self.installation_checklist_items)
        self.installation_checklist_progress.setText(f"{done}/{total} completed ({skipped} skipped)")

    def _save_installation_checklist_state(self) -> None:
        if self._is_loading_checklist_state:
            return

        checklist_state = {
            str(item.data(0, QtCore.Qt.UserRole) or item.text(0)): self.checklist_item_states.get(
                str(item.data(0, QtCore.Qt.UserRole) or item.text(0)),
                "CHECKED" if item.checkState(0) == QtCore.Qt.Checked else "UNCHECKED",
            )
            for item in self.installation_checklist_items
        }
        checklist_info = {field.field_id: self._get_checklist_field_value(field.field_id) for field in CHECKLIST_FIELDS}
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
                state = str(persisted_items.get(key, self.checklist_item_states.get(key, "UNCHECKED"))).upper()
                if state not in {"CHECKED", "UNCHECKED", "NA"}:
                    state = "UNCHECKED"
                self.checklist_item_states[key] = state
                item.setCheckState(0, QtCore.Qt.Checked if state == "CHECKED" else QtCore.Qt.Unchecked)
                if state == "NA":
                    self._set_checklist_item_status(key, "NA", "Not applicable")

            for key, widget in self.checklist_info_inputs.items():
                self._set_checklist_info_value(key, widget, persisted_info.get(key, ""))
        finally:
            self._is_loading_checklist_state = False

        for key in (HOSTNAME_FIELD_ID, FILE_NAME_FIELD_ID):
            value = self._get_checklist_info_text(key)
            self._last_autofill_values[key] = value

        self._apply_checklist_autofill()

    def _ensure_profile_storage(self) -> None:
        CHECKLIST_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        if not DEFAULT_PROFILE_FILE.exists():
            default_payload = {"items": {}, "info": {}}
            DEFAULT_PROFILE_FILE.write_text(json.dumps(default_payload, indent=2), encoding="utf-8")
            self._append(f"[INFO] Default profile initialized at: {DEFAULT_PROFILE_FILE.resolve()}")

    def _refresh_profile_selector(self) -> None:
        profiles = sorted(CHECKLIST_PROFILE_DIR.glob("*.json"))
        self.profile_selector.clear()
        for profile in profiles:
            self.profile_selector.addItem(profile.stem, str(profile))
        default_path = str(DEFAULT_PROFILE_FILE)
        idx = self.profile_selector.findData(default_path)
        if idx >= 0:
            self.profile_selector.setCurrentIndex(idx)
        self._update_profile_action_buttons()

    def _selected_profile_path(self) -> Path:
        data = self.profile_selector.currentData()
        if isinstance(data, str) and data:
            return Path(data)
        return DEFAULT_PROFILE_FILE

    def _update_profile_action_buttons(self) -> None:
        profile_path = self._selected_profile_path()
        can_delete = profile_path != DEFAULT_PROFILE_FILE and profile_path.exists()
        self.delete_profile_button.setEnabled(can_delete)

    def _save_profile(self) -> None:
        suggested_name = to_pascal_case_alnum(self._get_checklist_info_text(CLIENT_NAME_FIELD_ID)) or "Profile"
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Save profile")
        layout = QtWidgets.QVBoxLayout(dialog)

        name_label = QtWidgets.QLabel("Profile name:")
        name_input = QtWidgets.QLineEdit(suggested_name)
        layout.addWidget(name_label)
        layout.addWidget(name_input)

        button_box = QtWidgets.QDialogButtonBox()
        save_button = button_box.addButton("Save", QtWidgets.QDialogButtonBox.AcceptRole)
        default_button = button_box.addButton("Save as default", QtWidgets.QDialogButtonBox.ActionRole)
        cancel_button = button_box.addButton(QtWidgets.QDialogButtonBox.Cancel)
        layout.addWidget(button_box)

        save_as_default = False

        def _accept() -> None:
            dialog.accept()

        def _save_default() -> None:
            nonlocal save_as_default
            save_as_default = True
            dialog.accept()

        save_button.clicked.connect(_accept)
        default_button.clicked.connect(_save_default)
        cancel_button.clicked.connect(dialog.reject)

        if dialog.exec() != QtWidgets.QDialog.Accepted:
            self._append("[INFO] Save profile cancelled.")
            return

        input_name = to_pascal_case_alnum(name_input.text()) or suggested_name
        if save_as_default:
            profile_path = DEFAULT_PROFILE_FILE
        else:
            profile_name = f"{input_name}-{datetime.now().strftime('%y%m%d')}.json"
            profile_path = CHECKLIST_PROFILE_DIR / profile_name

        checklist_state = {
            str(item.data(0, QtCore.Qt.UserRole) or item.text(0)): self.checklist_item_states.get(
                str(item.data(0, QtCore.Qt.UserRole) or item.text(0)),
                "CHECKED" if item.checkState(0) == QtCore.Qt.Checked else "UNCHECKED",
            )
            for item in self.installation_checklist_items
        }
        checklist_info = {field.field_id: self._get_checklist_field_value(field.field_id) for field in CHECKLIST_FIELDS}
        save_checklist_state(profile_path, checklist_state, checklist_info)
        self._refresh_profile_selector()
        idx = self.profile_selector.findData(str(profile_path))
        if idx >= 0:
            self.profile_selector.setCurrentIndex(idx)
        if save_as_default:
            self._append(f"[INFO] Default profile saved to: {profile_path.resolve()}. Use Reload profile to apply saved profile values.")
        else:
            self._append(f"[INFO] Profile saved to: {profile_path.resolve()}. Use Reload profile to apply saved profile values.")

    def _reload_selected_profile(self) -> None:
        profile_path = self._selected_profile_path()
        try:
            persisted_items, persisted_info = load_checklist_state(profile_path)
        except (json.JSONDecodeError, OSError):
            self._append(f"[WARN] Could not load profile: {profile_path.name}")
            return

        self._is_loading_checklist_state = True
        try:
            for item in self.installation_checklist_items:
                key = str(item.data(0, QtCore.Qt.UserRole) or item.text(0))
                state = str(persisted_items.get(key, self.checklist_item_states.get(key, "UNCHECKED"))).upper()
                if state not in {"CHECKED", "UNCHECKED", "NA"}:
                    state = "UNCHECKED"
                self.checklist_item_states[key] = state
                item.setCheckState(0, QtCore.Qt.Checked if state == "CHECKED" else QtCore.Qt.Unchecked)
                if state == "NA":
                    self._set_checklist_item_status(key, "NA", "Not applicable")
                elif state == "UNCHECKED":
                    self._set_checklist_item_status(key, "PENDING", "Waiting")

            for key, widget in self.checklist_info_inputs.items():
                self._set_checklist_info_value(key, widget, persisted_info.get(key, ""))
        finally:
            self._is_loading_checklist_state = False

        self._apply_checklist_autofill()
        self._update_installation_checklist_progress()
        self._save_installation_checklist_state()
        self._append(f"[INFO] Profile reloaded: {profile_path.name}")

    def _delete_selected_profile(self) -> None:
        profile_path = self._selected_profile_path()
        if profile_path == DEFAULT_PROFILE_FILE:
            self._append("[WARN] Default profile cannot be deleted.")
            self._update_profile_action_buttons()
            return
        if not profile_path.exists():
            self._append(f"[WARN] Profile not found: {profile_path.name}")
            self._refresh_profile_selector()
            return

        confirmation = QtWidgets.QMessageBox.question(
            self,
            "Delete profile",
            f"Delete profile '{profile_path.stem}'? This cannot be undone.",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No,
        )
        if confirmation != QtWidgets.QMessageBox.Yes:
            self._append("[INFO] Delete profile cancelled.")
            return

        try:
            profile_path.unlink()
        except OSError as exc:
            self._append(f"[WARN] Failed to delete profile '{profile_path.name}': {exc}")
            return

        self._refresh_profile_selector()
        self._append(f"[INFO] Profile deleted: {profile_path.name}")

    def _apply_default_checklist_states(self) -> None:
        for task_id in DEFAULT_NA_ITEM_IDS:
            item = self.checklist_item_by_id.get(task_id)
            if item is None:
                continue
            state = "NA"
            self.checklist_item_states[task_id] = state
            item.setCheckState(0, QtCore.Qt.Unchecked)
            if state == "NA":
                self._set_checklist_item_status(task_id, "NA", "Not applicable")

    def _start_new_install(self) -> None:
        self._is_loading_checklist_state = True
        try:
            for item in self.installation_checklist_items:
                item.setCheckState(0, QtCore.Qt.Unchecked)
                task_id = item.data(0, QtCore.Qt.UserRole)
                if isinstance(task_id, str):
                    self.checklist_item_states[task_id] = "UNCHECKED"
                    self._set_checklist_item_status(task_id, "PENDING", "Waiting")
            for field_id, widget in self.checklist_info_inputs.items():
                self._set_checklist_info_value(field_id, widget, "")
            self._apply_default_checklist_states()
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

        self._append(f"[INFO] Report saved to: {Path(selected_path).resolve()}")
        self._open_text_file(selected_path, "Save Report")

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
            value = self._get_checklist_field_value(field.field_id)
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

        self._append(f"[INFO] Installation report exported to: {Path(selected_path).resolve()}")
        self._open_text_file(selected_path, "Export installation report")

    def _get_checklist_field_value(self, field_id: str) -> str:
        if field_id == HOSTNAME_FIELD_ID:
            return self._build_hostname_value()
        if field_id == DATE_FIELD_ID:
            return datetime.now().strftime("%Y-%m-%d")
        if field_id == FILE_NAME_FIELD_ID:
            return self._build_file_name_value()

        widget = self.checklist_info_inputs.get(field_id)
        return self._read_checklist_info_value(widget) if widget is not None else ""

    def _read_checklist_info_value(self, widget: QtWidgets.QWidget) -> str:
        if isinstance(widget, InstalledCardsInput):
            return widget.text_value().strip()
        if isinstance(widget, QtWidgets.QLineEdit):
            return widget.text().strip()
        if isinstance(widget, QtWidgets.QComboBox):
            return widget.currentText().strip()
        if isinstance(widget, QtWidgets.QDateEdit):
            return widget.date().toString("yyyy-MM-dd")
        return ""

    def _set_checklist_info_value(self, field_id: str, widget: QtWidgets.QWidget, value: str) -> None:
        if isinstance(widget, InstalledCardsInput):
            widget.set_values_from_text(value)
            return
        if isinstance(widget, QtWidgets.QLineEdit):
            widget.setText(value)
            return
        if isinstance(widget, QtWidgets.QComboBox):
            if widget.isEditable():
                self._add_combo_value_if_missing(widget, value)
                widget.setCurrentText(value)
                return
            if not value.strip():
                widget.setCurrentIndex(-1)
                return
            normalized_value = normalize_numbering_value(value)

            index = widget.findText(normalized_value)
            widget.setCurrentIndex(index if index >= 0 else -1)
            return
        if isinstance(widget, QtWidgets.QDateEdit):
            parsed_date = QtCore.QDate.fromString(value, "yyyy-MM-dd")
            widget.setDate(parsed_date if parsed_date.isValid() else QtCore.QDate.currentDate())

    def _add_combo_value_if_missing(self, widget: QtWidgets.QComboBox, value: str | None = None) -> None:
        candidate = (value if value is not None else widget.currentText()).strip()
        if not candidate:
            return

        existing_values = [widget.itemText(index) for index in range(widget.count())]
        for existing in existing_values:
            if existing.casefold() == candidate.casefold():
                if widget.isEditable():
                    widget.setCurrentText(existing)
                return

        widget.addItem(candidate)

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

    def _build_install_app_command(self, app: InstallApp) -> list[str]:
        return [
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

    def _resolve_copy_commands(self, task_key: str | None = None, app_key: str | None = None) -> list[list[str]]:
        if task_key is not None:
            action = self._task_command_sources.get(task_key)
            return action() if action is not None else []

        if app_key is not None:
            app = self._app_by_key.get(app_key)
            if app is not None:
                return [self._build_install_app_command(app)]

        return []

    def _build_copy_text(self, commands: list[list[str]], target_shell: str) -> str:
        snippets: list[str] = []
        for command in commands:
            if target_shell == "powershell" and _command_shell_kind(command) == "powershell":
                snippets.append(_extract_powershell_snippet(command))
            else:
                snippets.append(format_command(command))
        return "\n".join(snippets)

    def _copy_commands_to_clipboard(self, commands: list[list[str]], target_shell: str, label: str) -> None:
        snippet = self._build_copy_text(commands, target_shell)
        if not snippet.strip():
            QtWidgets.QMessageBox.information(self, "Copy code", "No command available to copy.")
            return

        clipboard = QtWidgets.QApplication.clipboard()
        if clipboard is None:
            QtWidgets.QMessageBox.warning(self, "Copy code", "Clipboard is not available.")
            return
        clipboard.setText(snippet)
        self._append(f"[INFO] Copied command snippet ({label}) to clipboard.")

    def _show_copy_code_context_menu(
        self,
        widget: QtWidgets.QWidget,
        position: QtCore.QPoint,
        task_key: str | None = None,
        app_key: str | None = None,
    ) -> None:
        commands = self._resolve_copy_commands(task_key=task_key, app_key=app_key)
        if not commands:
            return

        shell_kinds = {_command_shell_kind(command) for command in commands}
        menu = QtWidgets.QMenu(widget)
        if shell_kinds == {"powershell"}:
            copy_action = menu.addAction("Copy code (Powershell)")
            copy_action.triggered.connect(lambda: self._copy_commands_to_clipboard(commands, "powershell", "Powershell"))
        elif shell_kinds == {"cmd"}:
            copy_action = menu.addAction("Copy code (Cmd)")
            copy_action.triggered.connect(lambda: self._copy_commands_to_clipboard(commands, "cmd", "Cmd"))
        else:
            copy_action = menu.addAction("Copy code (Cmd/Powershell)")
            copy_action.triggered.connect(lambda: self._copy_commands_to_clipboard(commands, "cmd", "Cmd/Powershell"))

        menu.exec_(widget.mapToGlobal(position))

    def _open_manual_install_link(self, app_label: str, url: str) -> None:
        opened = QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
        if not opened:
            self._append(f"[WARN] Unable to open {app_label} website: {url}")

    def _open_text_file(self, file_path: str, dialog_title: str) -> None:
        opened = QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(file_path))
        if not opened:
            QtWidgets.QMessageBox.warning(self, dialog_title, f"Report saved but could not open file:\n{file_path}")

    def _append(self, text: str = "") -> None:
        self.output.appendPlainText(text)
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())
        if self._mirror_output_to_external_console:
            print(text, flush=True)

    def _append_external_console_only(self, text: str = "") -> None:
        if self._mirror_output_to_external_console:
            print(text, flush=True)

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
        app = QtWidgets.QApplication.instance()
        if app is not None:
            if running:
                if app.overrideCursor() is None:
                    app.setOverrideCursor(QtCore.Qt.WaitCursor)
            elif app.overrideCursor() is not None:
                app.restoreOverrideCursor()

        if running:
            self._set_external_console_visibility(True)
        else:
            self._set_external_console_visibility(False)

    def _set_external_console_visibility(self, visible: bool) -> None:
        if visible:
            self._external_console_visible = show_windows_console()
            self._mirror_output_to_external_console = self._external_console_visible
        else:
            self._external_console_visible = False
            self._mirror_output_to_external_console = False
            hide_windows_console()
        self._sync_external_console_button_label()

    def _sync_external_console_button_label(self) -> None:
        self.external_console_button.setText(
            "Hide external console" if self._external_console_visible else "Show external console"
        )

    def _toggle_external_console(self) -> None:
        self._set_external_console_visibility(not self._external_console_visible)

    def _start_worker(self, worker: SetupWorker) -> None:
        self._worker_thread = QtCore.QThread(self)
        self._worker = worker
        self._active_worker_mode = worker._mode
        self._worker.moveToThread(self._worker_thread)

        if worker._mode == "inspect":
            worker.log_line.connect(self._append)
        else:
            worker.log_line.connect(self._append_external_console_only)
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
        if self._active_worker_mode == "apply":
            self._append_external_console_only('[INFO] Cancel requested. Stopping after current command...')
        else:
            self._append('[INFO] Cancel requested. Stopping after current command...')
        self._worker.request_cancel()
        self.cancel_button.setEnabled(False)

    def _on_worker_completed(self, success: bool, reason: str) -> None:
        completed_mode = self._active_worker_mode
        if reason == 'cancelled':
            if completed_mode == "apply":
                self._append_external_console_only('[INFO] Operation cancelled.')
            else:
                self._append('[INFO] Operation cancelled.')
        elif not success:
            if completed_mode == "apply":
                self._append_external_console_only('[INFO] Operation finished with errors.')
            else:
                self._append('[INFO] Operation finished with errors.')
        self._set_execution_state(False)
        self._worker = None
        self._worker_thread = None
        self._active_worker_mode = ""
        if completed_mode == "apply" and reason != "cancelled":
            self._show_restart_prompt()

    def _show_restart_prompt(self) -> None:
        message = QtWidgets.QMessageBox(self)
        message.setIcon(QtWidgets.QMessageBox.Information)
        message.setWindowTitle("Restart may be needed")
        message.setText("Run completed. A restart may be needed.")
        restart_now = message.addButton("Restart now", QtWidgets.QMessageBox.AcceptRole)
        message.addButton("Restart later", QtWidgets.QMessageBox.RejectRole)
        message.exec_()
        if message.clickedButton() != restart_now:
            self._append("[INFO] Restart postponed by user.")
            return

        if not is_windows():
            self._append("[WARN] Restart now is only supported on Windows.")
            return

        rc, _ = run_command_with_options(["shutdown", "/r", "/t", "0"], timeout_sec=10)
        if rc != 0:
            self._append("[WARN] Failed to trigger immediate restart.")

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
            cmd = self._build_install_app_command(app)
            app_steps.append(ExecutionStep(label=app.label, commands=[cmd]))

        return selected_steps, app_steps

    def _hostname_requirements_met(self) -> bool:
        expected = build_hostname_value(
            self._get_checklist_info_text(CLIENT_NAME_FIELD_ID),
            self._get_checklist_info_text(COMPUTER_ROLE_FIELD_ID),
            self._get_checklist_info_text(NUMBERING_FIELD_ID),
        )
        return bool(expected) and self.rename_input.text().strip() == expected

    def _run_apply(self) -> None:
        if self.task_checkboxes['rename_pc'].isChecked() and not self._hostname_requirements_met():
            QtWidgets.QMessageBox.warning(
                self,
                "Missing hostname fields",
                "Rename computer is blocked until Client name, Computer role (4+ chars), and Numbering00 are set. Disable Rename computer to run the other tasks.",
            )
            return

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

    set_windows_app_user_model_id(APP_ID)
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_EXE_NAME)
    app.setApplicationDisplayName(APP_NAME)
    icon = load_app_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)
    app.setStyleSheet(load_stylesheet())
    validate_install_app_catalog()
    window = MainWindow()
    window.show()
    hide_windows_console()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
