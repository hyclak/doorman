import os
import socket
import tempfile

from doorman import sdnotify


def test_noop_without_socket(monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert sdnotify.notify("READY=1") is False


def test_sends_datagram(monkeypatch):
    # Short directory: macOS caps AF_UNIX paths at 104 bytes, and pytest's tmp_path is longer.
    with (
        tempfile.TemporaryDirectory(prefix="dm") as d,
        socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as srv,
    ):
        path = os.path.join(d, "n.sock")
        srv.bind(path)
        monkeypatch.setenv("NOTIFY_SOCKET", path)
        assert sdnotify.notify("WATCHDOG=1") is True
        assert srv.recv(64) == b"WATCHDOG=1"


def test_watchdog_interval(monkeypatch):
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    assert sdnotify.watchdog_interval_s() is None
    monkeypatch.setenv("WATCHDOG_USEC", "30000000")
    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid()))
    assert sdnotify.watchdog_interval_s() == 15
    monkeypatch.setenv("WATCHDOG_PID", "1")
    assert sdnotify.watchdog_interval_s() is None
