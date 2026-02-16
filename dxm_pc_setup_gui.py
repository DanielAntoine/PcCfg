#!/usr/bin/env python3
"""DXM PC Setup GUI

PyQt-based Windows setup utility inspired by the provided batch script.
- Inspect button: generate/read-only system report.
- Run button: execute selected configuration actions.
"""

from __future__ import annotations

import ctypes
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

        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)

        self.apply_tasks = self._build_tasks()
        self.task_checkboxes: dict[str, QtWidgets.QCheckBox] = {}
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

        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(self.inspect_button)
        btn_row.addWidget(self.run_button)
        btn_row.addWidget(self.clear_button)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.select_all_checkbox)
        layout.addWidget(self.tasks_group)
        layout.addLayout(btn_row)
        layout.addWidget(self.output)

        self.select_all_checkbox.stateChanged.connect(self._toggle_all)
        self.inspect_button.clicked.connect(self._run_inspect)
        self.run_button.clicked.connect(self._run_apply)
        self.clear_button.clicked.connect(self.output.clear)

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

    def _append(self, text: str = "") -> None:
        self.output.appendPlainText(text)
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

    def _toggle_all(self, state: int) -> None:
        checked = state == QtCore.Qt.Checked
        for cb in self.task_checkboxes.values():
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

        if not is_windows():
            self._append("[ERROR] This tool is intended for Windows.")
            return

        code, os_name = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).Caption\"")
        _, os_ver = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).Version\"")
        _, os_build = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).BuildNumber\"")
        if code == 0:
            self._append("System")
            self._append("-" * 60)
            self._append(f"OS        : {compact_single_line(os_name)}")
            self._append(f"Version   : {compact_single_line(os_ver)}")
            self._append(f"Build     : {compact_single_line(os_build)}")
        else:
            self._append("OS        : unable to query")
        self._append(f"Admin     : {'YES' if is_admin() else 'NO'}")
        self._append()

        self._append("Configuration checks")
        self._append("-" * 60)

        checks = [
            ("Active power plan", "powercfg /getactivescheme", parse_active_power_plan),
            ("Fast Startup", "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\" /v HiberbootEnabled", parse_registry_value),
            ("GameDVR enabled", "reg query \"HKCU\\System\\GameConfigStore\" /v GameDVR_Enabled", parse_registry_value),
            ("App capture enabled", "reg query \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR\" /v AppCaptureEnabled", parse_registry_value),
            ("Policy: AllowGameDVR", "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR", parse_registry_value),
            ("Visual effects level", "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\" /v VisualFXSetting", parse_registry_value),
            ("Desktop icon labels", "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v IconsOnly", parse_registry_value),
            ("Toast notifications", "reg query \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v ToastEnabled", parse_registry_value),
            ("Notification center", "reg query \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v DisableNotificationCenter", parse_registry_value),
        ]

        for title, cmd, parser in checks:
            rc, out = run_command(cmd)
            if rc == 0 and out:
                parsed = parser(out)
                value = parsed if parsed else compact_single_line(out)
                self._append(f"- {title:<24}: {value}")
            else:
                self._append(f"- {title:<24}: Unable to query")

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
        if self.task_checkboxes["rename_pc"].isChecked() and not self.rename_input.text().strip():
            selected = [t for t in selected if t.key != "rename_pc"]
            self._append("Rename computer step skipped (name is empty).")
            self._append()

        if not selected:
            self._append("No APPLY options selected.")
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
