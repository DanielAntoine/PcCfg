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
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
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

        self.tasks_group = QtWidgets.QGroupBox("APPLY Options")
        self.tasks_layout = QtWidgets.QVBoxLayout(self.tasks_group)
        for task in self.apply_tasks:
            cb = QtWidgets.QCheckBox(task.label)
            cb.setChecked(True)
            self.task_checkboxes[task.key] = cb
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
                label="Rename computer (optional; prompted during APPLY)",
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
        self._append(f"=== {APP_NAME} (INSPECT) ===")
        self._append(f"Time: {datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self._append(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        self._append()

        if not is_windows():
            self._append("[ERROR] This tool is intended for Windows.")
            return

        code, os_name = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).Caption\"")
        _, os_ver = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).Version\"")
        _, os_build = run_command("powershell -NoProfile -Command \"(Get-CimInstance Win32_OperatingSystem).BuildNumber\"")
        if code == 0:
            self._append(f"OS: {os_name} (Version {os_ver} / Build {os_build})")
        else:
            self._append("OS: unable to query")
        self._append(f"Admin: {'YES' if is_admin() else 'NO'}")
        self._append()

        checks = [
            ("Active power plan", "powercfg /getactivescheme"),
            ("Fast Startup (HiberbootEnabled)", "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\" /v HiberbootEnabled"),
            ("GameDVR_Enabled", "reg query \"HKCU\\System\\GameConfigStore\" /v GameDVR_Enabled"),
            ("AppCaptureEnabled", "reg query \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR\" /v AppCaptureEnabled"),
            ("AllowGameDVR", "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR"),
            ("VisualFXSetting", "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\" /v VisualFXSetting"),
            ("IconsOnly", "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v IconsOnly"),
            ("ToastEnabled", "reg query \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v ToastEnabled"),
            ("DisableNotificationCenter", "reg query \"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v DisableNotificationCenter"),
        ]

        for title, cmd in checks:
            self._append(f"[{title}]")
            rc, out = run_command(cmd)
            if rc == 0 and out:
                self._append(out)
            else:
                self._append("Unable to query")
            self._append()

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
        new_name, ok = QtWidgets.QInputDialog.getText(
            self,
            "Rename Computer",
            "Enter new computer name (leave empty to skip):",
        )
        if not ok or not new_name.strip():
            self._append("  Rename skipped.")
            return []

        sanitized = new_name.strip().replace("'", "")
        return [
            f"powershell -NoProfile -Command \"Rename-Computer -NewName '{sanitized}' -Force\""
        ]


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
