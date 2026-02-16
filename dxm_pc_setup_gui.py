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
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from PyQt5 import QtCore, QtWidgets


APP_VERSION = "1.0.0"
APP_NAME = f"DXM - PC Setup v{APP_VERSION} (PyQt)"


@dataclass
class ApplyTask:
    key: str
    label: str
    action: Callable[[], list[str]]


@dataclass
class InstallApp:
    key: str
    label: str
    winget_id: str
    category: str


def run_command(command: str) -> tuple[int, str]:
    """Run command with shell and return (return_code, output)."""
    proc = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    return proc.returncode, proc.stdout.strip()


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


def format_status_line(label: str, value: str, ok: bool) -> str:
    return f"{label:<28}: {value} [{status_tag(ok)}]"


def readable_timeout_seconds(seconds: int) -> str:
    """Format powercfg timeout values (reported in seconds) for display."""
    if seconds == 0:
        return "Disabled"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} sec"



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

        self.apps_group = QtWidgets.QGroupBox("Applications (winget)")
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
        self.save_report_button.clicked.connect(self._save_report_txt)

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
                action=lambda: ["powercfg /setactive SCHEME_MIN"],
            ),
            ApplyTask(
                key="power_timeouts",
                label="Configure timeouts (Sleep/Hibernate/Disk=Never, Monitor=30m)",
                action=lambda: [
                    "powercfg /hibernate off",
                    "powercfg /change standby-timeout-ac 0",
                    "powercfg /change standby-timeout-dc 0",
                    "powercfg /change hibernate-timeout-ac 0",
                    "powercfg /change hibernate-timeout-dc 0",
                    "powercfg /change disk-timeout-ac 0",
                    "powercfg /change disk-timeout-dc 0",
                    "powercfg /change monitor-timeout-ac 30",
                    "powercfg /change monitor-timeout-dc 30",
                ],
            ),
            ApplyTask(
                key="usb_suspend",
                label="Disable USB selective suspend (AC/DC)",
                action=lambda: [
                    "powercfg /setacvalueindex SCHEME_MIN 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0",
                    "powercfg /setdcvalueindex SCHEME_MIN 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0",
                    "powercfg /setactive SCHEME_MIN",
                ],
            ),
            ApplyTask(
                key="fast_startup",
                label="Disable Fast Startup",
                action=lambda: [
                    "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\" /v HiberbootEnabled /t REG_DWORD /d 0 /f"
                ],
            ),
            ApplyTask(
                key="game_dvr",
                label="Disable Game Bar / Game DVR",
                action=lambda: [
                    "reg add \"HKCU\\System\\GameConfigStore\" /v GameDVR_Enabled /t REG_DWORD /d 0 /f",
                    "reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR\" /v AppCaptureEnabled /t REG_DWORD /d 0 /f",
                    "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR /t REG_DWORD /d 0 /f",
                ],
            ),
            ApplyTask(
                key="visual_effects",
                label="Set visual effects (best performance, keep thumbnails)",
                action=lambda: [
                    "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\" /v VisualFXSetting /t REG_DWORD /d 2 /f",
                    "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v IconsOnly /t REG_DWORD /d 0 /f",
                ],
            ),
            ApplyTask(
                key="notifications",
                label="Disable Windows notifications (current user)",
                action=lambda: [
                    "reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v ToastEnabled /t REG_DWORD /d 0 /f",
                    "reg add \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v DisableNotificationCenter /t REG_DWORD /d 1 /f",
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

    def _run_inspect(self) -> None:
        self.inspect_button.setEnabled(False)
        self.run_button.setEnabled(False)
        try:
            self.run_inspect()
        finally:
            self.inspect_button.setEnabled(True)
            self.run_button.setEnabled(True)

    def _run_apply(self) -> None:
        self.inspect_button.setEnabled(False)
        self.run_button.setEnabled(False)
        try:
            self.run_apply()
        finally:
            self.inspect_button.setEnabled(True)
            self.run_button.setEnabled(True)

    def run_inspect(self) -> None:
        self._append("=" * 60)
        self._append(f"{APP_NAME} - INSPECT REPORT")
        self._append("=" * 60)
        self._append(f"Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._append(f"Computer  : {os.environ.get('COMPUTERNAME', 'Unknown')}")
        self._append()
        self._append("APPLY option status")
        self._append("-" * 60)
        for line in self._build_apply_status_lines():
            self._append(line)
        self._append()

        if not is_windows():
            self._append("[ERROR] This tool is intended for Windows.")
            return

        code, os_name = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).Caption\"")
        _, os_ver = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).Version\"")
        _, os_build = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).BuildNumber\"")
        _, os_ubr = run_command("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v UBR")
        _, os_display = run_command("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v DisplayVersion")
        if code == 0:
            self._append("System")
            self._append("-" * 60)
            self._append(f"OS        : {compact_single_line(os_name)}")
            self._append(f"Version   : {compact_single_line(os_ver)}")
            self._append(f"Build     : {compact_single_line(os_build)}")
            ubr_value = parse_registry_int(parse_registry_value(os_ubr))
            display_value = parse_registry_value(os_display)
            if display_value:
                self._append(f"Release   : {display_value}")
            current_full_build = "Unknown"
            if ubr_value is not None:
                current_full_build = f"{compact_single_line(os_build)}.{ubr_value}"
                self._append(f"Full build: {current_full_build}")
        else:
            self._append("OS        : unable to query")
        self._append(f"Admin     : {'YES' if is_admin() else 'NO'}")
        self._append()

        self._append("Target video cards (NVIDIA / AMD / Blackmagic)")
        self._append("-" * 60)
        gpu_cmd = (
            "powershell -NoProfile -Command \"Get-CimInstance Win32_VideoController | "
            "Select-Object Name,DriverVersion,DriverDate,PNPDeviceID | ConvertTo-Json -Compress\""
        )
        _, gpu_out = run_command(gpu_cmd)
        gpus = [gpu for gpu in parse_json_payload(gpu_out) if is_target_video_device(str(gpu.get("Name", "")), str(gpu.get("PNPDeviceID", "")))]
        if gpus:
            self._append(f"Found     : {len(gpus)} matching device(s)")
            for gpu in gpus:
                name = str(gpu.get("Name", "Unknown")).strip() or "Unknown"
                version = str(gpu.get("DriverVersion", "Unknown")).strip() or "Unknown"
                date = format_driver_date(str(gpu.get("DriverDate", "")))
                vendor = guess_gpu_vendor(name)
                lookup = get_vendor_driver_lookup_hint(vendor)
                self._append(f"GPU       : {name}")
                self._append(f"  Driver  : {version}")
                self._append(f"  Date    : {date}")
                self._append(f"  Latest  : check {vendor} site -> {lookup}")
        else:
            self._append("GPU       : No NVIDIA/AMD/Blackmagic video card detected")
        self._append()


    def _query_registry_dword(self, key_path: str, value_name: str) -> int | None:
        _, output = run_command(f'reg query "{key_path}" /v {value_name}')
        return parse_registry_int(parse_registry_value(output))

    def _query_power_setting_indices(self, subgroup_guid: str, setting_guid: str) -> tuple[int | None, int | None]:
        _, output = run_command(f"powercfg /query scheme_current {subgroup_guid} {setting_guid}")
        return parse_powercfg_indices(output)

    def _format_power_dual_status(
        self,
        label: str,
        subgroup_guid: str,
        setting_guid: str,
        expected_ac: int,
        expected_dc: int,
        value_formatter: Callable[[int], str],
    ) -> str:
        ac_value, dc_value = self._query_power_setting_indices(subgroup_guid, setting_guid)
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

    def _build_apply_status_lines(self) -> list[str]:
        lines: list[str] = []

        _, active_plan_out = run_command("powercfg /getactivescheme")
        active_plan = parse_active_power_plan(active_plan_out)
        high_perf_guid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        active_line = compact_single_line(active_plan_out).lower()
        active_ok = high_perf_guid in active_line or "high performance" in active_line
        lines.append(format_status_line("Active power plan", active_plan, active_ok))

        lines.append(
            self._format_power_dual_status(
                "Sleep timeout",
                "SUB_SLEEP",
                "STANDBYIDLE",
                expected_ac=0,
                expected_dc=0,
                value_formatter=readable_timeout_seconds,
            )
        )
        lines.append(
            self._format_power_dual_status(
                "Hibernate timeout",
                "SUB_SLEEP",
                "HIBERNATEIDLE",
                expected_ac=0,
                expected_dc=0,
                value_formatter=readable_timeout_seconds,
            )
        )
        lines.append(
            self._format_power_dual_status(
                "Disk timeout",
                "SUB_DISK",
                "DISKIDLE",
                expected_ac=0,
                expected_dc=0,
                value_formatter=readable_timeout_seconds,
            )
        )
        lines.append(
            self._format_power_dual_status(
                "Monitor timeout",
                "SUB_VIDEO",
                "VIDEOIDLE",
                expected_ac=1800,
                expected_dc=1800,
                value_formatter=readable_timeout_seconds,
            )
        )
        lines.append(
            self._format_power_dual_status(
                "USB selective suspend",
                "2a737441-1930-4402-8d77-b2bebba308a3",
                "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
                expected_ac=0,
                expected_dc=0,
                value_formatter=lambda value: "Disabled" if value == 0 else f"Enabled ({value})",
            )
        )

        fast_startup = self._query_registry_dword(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
            "HiberbootEnabled",
        )
        if fast_startup is None:
            lines.append(format_status_line("Fast Startup", "Unable to query", False))
        else:
            lines.append(format_status_line("Fast Startup", "Disabled" if fast_startup == 0 else "Enabled", fast_startup == 0))

        game_dvr_policy = self._query_registry_dword(
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR",
            "AllowGameDVR",
        )
        if game_dvr_policy is None:
            lines.append(format_status_line("Policy: AllowGameDVR", "Unable to query", False))
        else:
            policy_value = "Disabled" if game_dvr_policy == 0 else "Enabled"
            lines.append(format_status_line("Policy: AllowGameDVR", policy_value, game_dvr_policy == 0))

        visual_fx = self._query_registry_dword(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects",
            "VisualFXSetting",
        )
        if visual_fx is None:
            lines.append(format_status_line("Visual effects", "Unable to query", False))
        else:
            visual_fx_value = "Best performance" if visual_fx == 2 else f"Custom ({visual_fx})"
            lines.append(format_status_line("Visual effects", visual_fx_value, visual_fx == 2))

        thumbnails = self._query_registry_dword(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
            "IconsOnly",
        )
        if thumbnails is None:
            lines.append(format_status_line("Thumbnail previews", "Unable to query", False))
        else:
            lines.append(format_status_line("Thumbnail previews", "Enabled" if thumbnails == 0 else "Disabled", thumbnails == 0))

        toast_enabled = self._query_registry_dword(
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
            "ToastEnabled",
        )
        if toast_enabled is None:
            lines.append(format_status_line("Toast notifications", "Unable to query", False))
        else:
            lines.append(format_status_line("Toast notifications", "Disabled" if toast_enabled == 0 else "Enabled", toast_enabled == 0))

        notification_center = self._query_registry_dword(
            "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
            "DisableNotificationCenter",
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

        target_name = self.rename_input.text().strip()
        if target_name:
            current_name = os.environ.get("COMPUTERNAME", "Unknown")
            lines.append(format_status_line("Rename computer", f"Current={current_name}, Target={target_name}", current_name.lower() == target_name.lower()))
        return lines

    def run_apply(self) -> None:
        self._append("=== DXM PC Setup (APPLY) ===")
        self._append(f"Time: {datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self._append(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        self._append()

        if not is_windows():
            self._append("[ERROR] This tool is intended for Windows.")
            return
        if not is_admin():
            self._append("[ERROR] Please run this script as Administrator for APPLY mode.")
            return

        selected = [t for t in self.apply_tasks if self.task_checkboxes[t.key].isChecked()]
        selected_apps = [a for a in self.install_apps if self.app_checkboxes[a.key].isChecked()]
        if self.task_checkboxes["rename_pc"].isChecked() and not self.rename_input.text().strip():
            selected = [t for t in selected if t.key != "rename_pc"]
            self._append("Rename computer step skipped (name is empty).")
            self._append()

        if not selected and not selected_apps:
            self._append("No APPLY options or application installs selected.")
            return

        total = len(selected)
        for idx, task in enumerate(selected, start=1):
            self._append(f"[{idx}/{total}] {task.label}")
            for cmd in task.action():
                rc, out = run_command(cmd)
                status = "OK" if rc == 0 else f"FAIL (exit {rc})"
                self._append(f"  $ {cmd}")
                self._append(f"    -> {status}")
                if out:
                    self._append(f"    {out}")
            self._append()

        if selected_apps:
            self._append("Applications installation")
            self._append("-" * 30)
            for idx, app in enumerate(selected_apps, start=1):
                cmd = f"winget install --id {app.winget_id} -e --accept-package-agreements --accept-source-agreements"
                self._append(f"[{idx}/{len(selected_apps)}] {app.label}")
                rc, out = run_command(cmd)
                status = "OK" if rc == 0 else f"FAIL (exit {rc})"
                self._append(f"  $ {cmd}")
                self._append(f"    -> {status}")
                if out:
                    self._append(f"    {out}")
                self._append()

        self._append("DONE. Reboot is recommended (required if computer rename was applied).")

    def _rename_computer_action(self) -> list[str]:
        new_name = self.rename_input.text().strip()
        if not new_name:
            return []

        sanitized = new_name.strip().replace("'", "")
        return [
            f"powershell -NoProfile -Command \"Rename-Computer -NewName '{sanitized}' -Force\""
        ]


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
