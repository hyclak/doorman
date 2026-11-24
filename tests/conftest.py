from __future__ import annotations

import ipaddress
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from doorman.clock import FrozenClock

TZ = ZoneInfo("America/New_York")


def at(y: int, mo: int, d: int, h: int = 0, mi: int = 0, s: int = 0) -> datetime:
    return datetime(y, mo, d, h, mi, s, tzinfo=TZ)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(at(2026, 11, 22, 9, 0))


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """No real DNS in tests: IP literals resolve to themselves, names in FAKE_DNS to their
    entries, anything else fails."""
    from doorman import notify_urls

    def resolve(host):
        try:
            return [str(ipaddress.ip_address(host.strip("[]")))]
        except ValueError:
            pass
        if host in FAKE_DNS:
            return FAKE_DNS[host]
        raise OSError("no such host")

    monkeypatch.setattr(notify_urls, "resolve", resolve)


FAKE_DNS = {
    "ntfy.sh": ["159.203.148.75"],
    "ntfy.internal.example": ["10.10.40.5"],
    "rebind.example": ["93.184.215.14", "127.0.0.1"],
}
