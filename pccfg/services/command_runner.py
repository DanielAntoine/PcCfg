from __future__ import annotations

import shlex
import subprocess
import threading
from queue import Empty, Queue
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
    on_output: Callable[[str], None] | None = None,
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

    output_lines: list[str] = []
    output_queue: Queue[str | None] = Queue()

    def enqueue_output() -> None:
        if proc.stdout is None:
            output_queue.put(None)
            return
        for line in proc.stdout:
            output_queue.put(line)
        output_queue.put(None)

    stdout_thread = threading.Thread(target=enqueue_output, daemon=True)
    stdout_thread.start()

    deadline = None if timeout_sec is None else datetime.now().timestamp() + timeout_sec
    stream_finished = False
    while True:
        while True:
            try:
                line = output_queue.get_nowait()
            except Empty:
                break

            if line is None:
                stream_finished = True
                continue

            stripped = line.rstrip("\r\n")
            output_lines.append(stripped)
            if on_output:
                on_output(stripped)

        if cancel_requested and cancel_requested():
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            stdout_thread.join(timeout=1)
            return COMMAND_CANCEL_EXIT_CODE, "\n".join(output_lines).strip()

        if deadline is not None and datetime.now().timestamp() >= deadline:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            stdout_thread.join(timeout=1)
            return COMMAND_TIMEOUT_EXIT_CODE, "\n".join(output_lines).strip()

        rc = proc.poll()
        if rc is not None and stream_finished:
            stdout_thread.join(timeout=1)
            return rc, "\n".join(output_lines).strip()

        QtCore.QThread.msleep(max(1, int(poll_interval_sec * 1000)))


def format_command(args: list[str]) -> str:
    """Create a readable command line string for logging."""
    return subprocess.list2cmdline(args)
