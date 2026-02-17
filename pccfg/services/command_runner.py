from __future__ import annotations

import shlex
import subprocess
from datetime import datetime
from typing import Callable, overload

from PyQt5 import QtCore

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
