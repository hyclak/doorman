"""Time windows: allow windows for scheduled users / guest links, and quiet-hour windows.

Kinds:
  once    - absolute start_at .. end_at (aware datetimes)
  daily   - start_time .. end_time every day, optionally between valid_from/valid_until
  weekly  - like daily, but only on the listed weekdays (0 = Monday)

A daily/weekly window whose end_time <= start_time crosses midnight; the occurrence
belongs to the day it starts on (a Friday 21:00-06:00 window covers Saturday 03:00).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, tzinfo

DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
ALL_DAYS = frozenset(range(7))


@dataclass(frozen=True)
class Window:
    kind: str
    start_at: datetime | None = None
    end_at: datetime | None = None
    start_time: time | None = None
    end_time: time | None = None
    days: frozenset[int] = field(default=ALL_DAYS)
    valid_from: date | None = None
    valid_until: date | None = None
    id: int | None = None
    label: str = ""

    def __post_init__(self) -> None:
        if self.kind == "once":
            if not (self.start_at and self.end_at) or self.end_at <= self.start_at:
                raise ValueError("A one-time window needs a start before its end.")
            if self.start_at.tzinfo is None or self.end_at.tzinfo is None:
                raise ValueError("One-time windows need timezone-aware datetimes.")
        elif self.kind in ("daily", "weekly"):
            if self.start_time is None or self.end_time is None:
                raise ValueError("A recurring window needs start and end times.")
            if self.kind == "weekly" and not self.days:
                raise ValueError("A weekly window needs at least one day.")
            if self.valid_from and self.valid_until and self.valid_until < self.valid_from:
                raise ValueError("The end date is before the start date.")
        else:
            raise ValueError(f"Unknown window kind {self.kind!r}")

    def _day_ok(self, d: date) -> bool:
        if self.valid_from and d < self.valid_from:
            return False
        if self.valid_until and d > self.valid_until:
            return False
        return self.kind == "daily" or d.weekday() in self.days

    def _occurrence_for(self, d: date, tz: tzinfo) -> tuple[datetime, datetime]:
        assert self.start_time and self.end_time
        start = datetime.combine(d, self.start_time, tz)
        end_day = d if self.end_time > self.start_time else d + timedelta(days=1)
        end = datetime.combine(end_day, self.end_time, tz)
        return start, end

    def occurrence_at(self, now: datetime) -> tuple[datetime, datetime] | None:
        """The (start, end) of the occurrence containing ``now``, or None."""
        if self.kind == "once":
            assert self.start_at and self.end_at
            return (self.start_at, self.end_at) if self.start_at <= now < self.end_at else None
        tz = now.tzinfo
        assert tz is not None
        today = now.date()
        for d in (today, today - timedelta(days=1)):
            if not self._day_ok(d):
                continue
            start, end = self._occurrence_for(d, tz)
            if start <= now < end:
                return start, end
        return None

    def next_start_after(self, now: datetime, horizon_days: int = 400) -> datetime | None:
        if self.kind == "once":
            assert self.start_at
            return self.start_at if self.start_at > now else None
        tz = now.tzinfo
        assert tz is not None
        for i in range(horizon_days):
            d = now.date() + timedelta(days=i)
            if self.valid_until and d > self.valid_until:
                return None
            if self._day_ok(d):
                start, _ = self._occurrence_for(d, tz)
                if start > now:
                    return start
        return None

    def is_expired(self, now: datetime) -> bool:
        if self.kind == "once":
            assert self.end_at
            return self.end_at <= now
        if self.valid_until is None:
            return False
        last_end = self._occurrence_for(self.valid_until, now.tzinfo or now.astimezone().tzinfo)[1]  # type: ignore[arg-type]
        return last_end <= now

    def describe(self) -> str:
        if self.kind == "once":
            assert self.start_at and self.end_at
            s, e = self.start_at, self.end_at
            if s.date() == e.date() or (e - s <= timedelta(days=1) and e.time() <= s.time()):
                return f"{fmt_date(s)}, {fmt_time(s.time())}–{fmt_time(e.time())}"
            return f"{fmt_date(s)} {fmt_time(s.time())} – {fmt_date(e)} {fmt_time(e.time())}"
        assert self.start_time and self.end_time
        times = f"{fmt_time(self.start_time)}–{fmt_time(self.end_time)}"
        when = "Every day" if self.kind == "daily" or self.days == ALL_DAYS else describe_days(self.days)
        out = f"{when}, {times}"
        if self.valid_from or self.valid_until:
            a = fmt_date(self.valid_from) if self.valid_from else "now"
            b = fmt_date(self.valid_until) if self.valid_until else "no end"
            out += f" ({a} to {b})"
        return out


def active_occurrence(windows: Iterable[Window], now: datetime) -> tuple[datetime, datetime] | None:
    """The active occurrence with the latest end, if any window contains ``now``."""
    best: tuple[datetime, datetime] | None = None
    for w in windows:
        occ = w.occurrence_at(now)
        if occ and (best is None or occ[1] > best[1]):
            best = occ
    return best


def next_start(windows: Iterable[Window], now: datetime) -> datetime | None:
    starts = [s for w in windows if (s := w.next_start_after(now)) is not None]
    return min(starts) if starts else None


def next_midnight(now: datetime) -> datetime:
    tz = now.tzinfo
    return datetime.combine(now.date() + timedelta(days=1), time(0, 0), tz)


# ---- formatting -------------------------------------------------------------------------------


def fmt_time(t: time) -> str:
    h = t.hour % 12 or 12
    suffix = "AM" if t.hour < 12 else "PM"
    return f"{h}:{t.minute:02d} {suffix}" if t.minute else f"{h} {suffix}"


def fmt_date(d: date | datetime) -> str:
    return f"{d:%a} {d:%b} {d.day}, {d.year}"


def describe_days(days: frozenset[int]) -> str:
    if days == frozenset(range(5)):
        return "Weekdays"
    if days == frozenset({5, 6}):
        return "Weekends"
    return ", ".join(DAY_NAMES[d] for d in sorted(days))


# ---- persistence ------------------------------------------------------------------------------


def parse_hhmm(value: str) -> time:
    hh, mm = value.strip().split(":")[:2]
    return time(int(hh), int(mm))


def from_row(row: sqlite3.Row) -> Window:
    def dt(v: str | None) -> datetime | None:
        return datetime.fromisoformat(v) if v else None

    def d(v: str | None) -> date | None:
        return date.fromisoformat(v) if v else None

    return Window(
        kind=row["kind"],
        start_at=dt(row["start_at"]),
        end_at=dt(row["end_at"]),
        start_time=parse_hhmm(row["start_time"]) if row["start_time"] else None,
        end_time=parse_hhmm(row["end_time"]) if row["end_time"] else None,
        days=frozenset(int(x) for x in row["days"].split(",") if x != ""),
        valid_from=d(row["valid_from"]),
        valid_until=d(row["valid_until"]),
        id=row["id"],
        label=row["label"],
    )


def to_params(w: Window) -> dict[str, object]:
    return {
        "kind": w.kind,
        "start_at": w.start_at.isoformat() if w.start_at else None,
        "end_at": w.end_at.isoformat() if w.end_at else None,
        "start_time": w.start_time.strftime("%H:%M") if w.start_time else None,
        "end_time": w.end_time.strftime("%H:%M") if w.end_time else None,
        "days": ",".join(str(x) for x in sorted(w.days)),
        "valid_from": w.valid_from.isoformat() if w.valid_from else None,
        "valid_until": w.valid_until.isoformat() if w.valid_until else None,
        "label": w.label,
    }
