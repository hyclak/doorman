from __future__ import annotations

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
