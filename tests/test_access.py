from doorman.access import CLOCK_NOT_SYNCED, Action, Principal, decide, permitted_actions
from doorman.schedules import Window

from .conftest import at

WINDOW = Window("once", start_at=at(2026, 11, 22, 10), end_at=at(2026, 11, 22, 12))


def user(role, **kw):
    return Principal("user", 1, "u", role=role, **kw)


def test_admin_and_household_always_allowed():
    for role in ("admin", "household"):
        assert decide(user(role), Action.OPEN, at(2026, 11, 22, 3), clock_synced=False)


def test_viewer_never_operates():
    d = decide(user("viewer"), Action.CLOSE, at(2026, 11, 22, 11), True)
    assert not d and "view" in d.reason


def test_disabled_denied():
    assert not decide(user("admin", disabled=True), Action.OPEN, at(2026, 11, 22, 11), True)


def test_scheduled_inside_and_outside_window():
    p = user("scheduled", windows=(WINDOW,))
    assert decide(p, Action.OPEN, at(2026, 11, 22, 10, 30), True)
    d = decide(p, Action.OPEN, at(2026, 11, 22, 12, 0), True)
    assert not d and "no upcoming" in d.reason


def test_scheduled_denied_until_clock_synced():
    p = user("scheduled", windows=(WINDOW,))
    d = decide(p, Action.OPEN, at(2026, 11, 22, 10, 30), clock_synced=False)
    assert not d and d.reason == CLOCK_NOT_SYNCED


def test_guest_late_close_until_midnight():
    p = Principal("link", 5, "cleaner", role="guest", windows=(WINDOW,), late_close_until=at(2026, 11, 23, 0))
    after = at(2026, 11, 22, 15)
    assert decide(p, Action.CLOSE, after, True)
    assert not decide(p, Action.OPEN, after, True)
    assert not decide(p, Action.CRACK, after, True)
    assert not decide(p, Action.CLOSE, at(2026, 11, 23, 0, 1), True)


def test_guest_without_redemption_gets_no_late_close():
    p = Principal("link", 5, "cleaner", role="guest", windows=(WINDOW,))
    assert not decide(p, Action.CLOSE, at(2026, 11, 22, 15), True)


def test_api_scopes():
    ro = Principal("api", 1, "ha", scopes=frozenset({"read"}))
    rw = Principal("api", 2, "ha", scopes=frozenset({"read", "operate"}))
    assert not decide(ro, Action.OPEN, at(2026, 11, 22, 3), True)
    assert decide(rw, Action.OPEN, at(2026, 11, 22, 3), True)


def test_permitted_actions_filters_and_explains():
    p = Principal("link", 5, "cleaner", role="guest", windows=(WINDOW,), late_close_until=at(2026, 11, 23, 0))
    acts, reason = permitted_actions(p, [Action.OPEN, Action.CRACK], at(2026, 11, 22, 15), True)
    assert acts == [] and reason
    acts, _ = permitted_actions(p, [Action.CLOSE], at(2026, 11, 22, 15), True)
    assert acts == [Action.CLOSE]
