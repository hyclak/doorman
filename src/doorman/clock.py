"""Wall clock, monotonic clock and NTP-sync status, injectable for tests."""

from __future__ import annotations

import subprocess
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo


class Clock:
    def __init__(self, tz: str = "America/New_York", assume_synced: bool = False) -> None:
        self.tz = ZoneInfo(tz)
        self._assume_synced = assume_synced
        self._synced_cache: tuple[float, bool] | None = None

    def now(self) -> datetime:
        return datetime.now(self.tz)

    def monotonic(self) -> float:
        return time.monotonic()

    def synced(self) -> bool:
        """True once systemd-timesyncd (or chrony) reports the clock is NTP-synchronized.

        The Pi has no battery-backed clock, so after a power cut it may run on a stale
        time until the network is back. Time-limited access is refused until this is True.
        """
        if self._assume_synced:
            return True
        now = time.monotonic()
        if self._synced_cache and now - self._synced_cache[0] < 30:
            return self._synced_cache[1]
        try:
            out = subprocess.run(
                ["/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            ).stdout.strip()
            synced = out == "yes"
        except (OSError, subprocess.SubprocessError):
            synced = False
        self._synced_cache = (now, synced)
        return synced


class FrozenClock(Clock):
    """Manually advanced clock for tests and simulations."""

    def __init__(self, start: datetime, synced: bool = True) -> None:
        assert start.tzinfo is not None
        self.tz = start.tzinfo  # type: ignore[assignment]
        self._now = start
        self._mono = 1000.0
        self.is_synced = synced

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def synced(self) -> bool:
        return self.is_synced

    def advance(self, seconds: float = 0, **kw: float) -> None:
        delta = timedelta(seconds=seconds, **kw)
        self._now += delta
        self._mono += delta.total_seconds()

    def set(self, when: datetime) -> None:
        self._mono += (when - self._now).total_seconds()
        self._now = when
