"""Parsing shared form inputs (time windows)."""

from __future__ import annotations

from datetime import date, datetime, timedelta, tzinfo
from typing import Any

from doorman.schedules import ALL_DAYS, Window, parse_hhmm


class FormError(ValueError):
    pass


def _get(data: dict[str, Any], key: str) -> str:
    v = data.get(key, "")
    if isinstance(v, list):
        v = v[0] if v else ""
    return str(v).strip()


def _days(data: dict[str, Any]) -> frozenset[int]:
    raw = data.get("days", [])
    if isinstance(raw, str):
        raw = [raw]
    try:
        return frozenset(int(d) for d in raw if str(d).isdigit() and 0 <= int(d) <= 6)
    except ValueError as e:
        raise FormError("Invalid day.") from e


def _date(v: str) -> date | None:
    if not v:
        return None
    try:
        return date.fromisoformat(v)
    except ValueError as e:
        raise FormError("Use a valid date.") from e


def parse_window(
    data: dict[str, Any], tz: tzinfo, allow_kinds: tuple[str, ...] = ("once", "daily", "weekly")
) -> Window:
    kind = _get(data, "kind") or "once"
    if kind not in allow_kinds:
        raise FormError("Pick a window type.")
    label = _get(data, "label")[:60]
    try:
        start_t = parse_hhmm(_get(data, "start_time"))
        end_t = parse_hhmm(_get(data, "end_time"))
    except (ValueError, IndexError) as e:
        raise FormError("Enter start and end times.") from e
    try:
        if kind == "once":
            d = _date(_get(data, "date"))
            if d is None:
                raise FormError("Pick a date.")
            end_d = _date(_get(data, "end_date")) or (d if end_t > start_t else d + timedelta(days=1))
            return Window(
                "once",
                start_at=datetime.combine(d, start_t, tz),
                end_at=datetime.combine(end_d, end_t, tz),
                label=label,
            )
        days = ALL_DAYS if kind == "daily" else _days(data)
        return Window(
            kind,
            start_time=start_t,
            end_time=end_t,
            days=days,
            valid_from=_date(_get(data, "valid_from")),
            valid_until=_date(_get(data, "valid_until")),
            label=label,
        )
    except ValueError as e:
        raise FormError(str(e)) from e
