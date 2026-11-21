from datetime import date, time

import pytest

from doorman.schedules import Window, active_occurrence, next_midnight, next_start

from .conftest import at


def once(s, e):
    return Window("once", start_at=s, end_at=e)


def test_once_window_bounds():
    w = once(at(2026, 11, 22, 10), at(2026, 11, 22, 12))
    assert w.occurrence_at(at(2026, 11, 22, 9, 59)) is None
    assert w.occurrence_at(at(2026, 11, 22, 10)) == (at(2026, 11, 22, 10), at(2026, 11, 22, 12))
    assert w.occurrence_at(at(2026, 11, 22, 11, 59)) is not None
    assert w.occurrence_at(at(2026, 11, 22, 12)) is None  # end is exclusive
    assert w.describe() == "Sun Nov 22, 2026, 10 AM–12 PM"


def test_once_requires_order():
    with pytest.raises(ValueError):
        once(at(2026, 11, 22, 12), at(2026, 11, 22, 10))


def test_weekly_window_days():
    w = Window("weekly", start_time=time(9), end_time=time(12), days=frozenset({1}))  # Tuesdays
    assert w.occurrence_at(at(2026, 11, 24, 10)) is not None  # Tue
    assert w.occurrence_at(at(2026, 11, 25, 10)) is None  # Wed
    assert w.describe() == "Tue, 9 AM–12 PM"


def test_overnight_window_belongs_to_start_day():
    # Fridays 9 PM - 6 AM
    w = Window("weekly", start_time=time(21), end_time=time(6), days=frozenset({4}))
    assert w.occurrence_at(at(2026, 11, 27, 22)) is not None  # Fri 10 PM
    assert w.occurrence_at(at(2026, 11, 28, 3)) is not None  # Sat 3 AM (Friday's occurrence)
    assert w.occurrence_at(at(2026, 11, 28, 22)) is None  # Sat 10 PM
    assert w.occurrence_at(at(2026, 11, 27, 3)) is None  # Fri 3 AM (Thursday not listed)


def test_daily_with_date_range():
    w = Window(
        "daily",
        start_time=time(7),
        end_time=time(9),
        valid_from=date(2026, 12, 1),
        valid_until=date(2026, 12, 3),
    )
    assert w.occurrence_at(at(2026, 11, 30, 8)) is None
    assert w.occurrence_at(at(2026, 12, 1, 8)) is not None
    assert w.occurrence_at(at(2026, 12, 3, 8)) is not None
    assert w.occurrence_at(at(2026, 12, 4, 8)) is None
    assert w.is_expired(at(2026, 12, 3, 9))
    assert not w.is_expired(at(2026, 12, 3, 8))


def test_dst_fall_back_window():
    # Nov 1 2026 is the DST change in the US; a 1 AM - 3 AM window still contains 2:30 AM.
    w = Window("daily", start_time=time(1), end_time=time(3))
    assert w.occurrence_at(at(2026, 11, 1, 2, 30)) is not None


def test_active_occurrence_picks_latest_end():
    a = once(at(2026, 11, 22, 10), at(2026, 11, 22, 11))
    b = once(at(2026, 11, 22, 10, 30), at(2026, 11, 22, 13))
    assert active_occurrence([a, b], at(2026, 11, 22, 10, 45))[1] == at(2026, 11, 22, 13)


def test_next_start_and_midnight():
    w = Window("weekly", start_time=time(9), end_time=time(12), days=frozenset({1}))
    assert next_start([w], at(2026, 11, 22, 9)) == at(2026, 11, 24, 9)
    assert next_midnight(at(2026, 11, 22, 23, 30)) == at(2026, 11, 23, 0)
