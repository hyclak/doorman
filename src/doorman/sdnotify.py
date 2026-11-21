"""Minimal systemd notify client (READY / WATCHDOG) with no dependencies.

Does nothing unless systemd set NOTIFY_SOCKET, so it is safe in development and tests.
"""

from __future__ import annotations

import os
import socket


def notify(message: str) -> bool:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):  # abstract namespace socket
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(message.encode())
        return True
    except OSError:
        return False


def watchdog_interval_s() -> float | None:
    """Half of WatchdogSec, i.e. how often to ping; None when the watchdog is off."""
    usec = os.environ.get("WATCHDOG_USEC")
    if not usec or not usec.isdigit():
        return None
    pid = os.environ.get("WATCHDOG_PID")
    if pid and pid.isdigit() and int(pid) != os.getpid():
        return None
    return int(usec) / 1_000_000 / 2
