from datetime import time

import pytest

from doorman.alerts import AlertEngine, compute_stop_at
from doorman.db import Database
from doorman.door import DoorState, Snapshot
from doorman.notify import EventType, Message, Notifier
from doorman.schedules import Window
from doorman.settings import Settings
from doorman.stats import Stats
from doorman.store import Store

from .conftest import at

QUIET = Window("daily", start_time=time(21), end_time=time(6))


class FakeNotifier:
    def __init__(self):
        self.msgs = []

    def publish(self, event, title, body=""):
        self.msgs.append((event, title, body))


def snap(state, open_since=None):
    return Snapshot(
        state,
        state.value,
        state == DoorState.CLOSED,
        at(2026, 11, 22),
        open_since,
        [],
        "",
        "pat",
        "user",
        None,
    )


@pytest.fixture
def engine(tmp_path):
    db = Database(tmp_path / "a.sqlite")
    db.migrate()
    settings = Settings(db)
    settings.set_many(
        {"quiet.reminder_interval_min": 15, "quiet.max_reminders": 2, "alerts.open_too_long_min": 30}
    )
    n = FakeNotifier()
    return AlertEngine(n, settings, lambda: [QUIET]), n, settings


def titles(n, event=EventType.QUIET_HOURS):
    return [t for e, t, _ in n.msgs if e == event]


def test_quiet_alert_reminders_then_gives_up(engine):
    eng, n, _ = engine
    open_ = snap(DoorState.OPEN, at(2026, 11, 22, 20))
    eng.tick(at(2026, 11, 22, 20, 59), open_, None)
    assert titles(n) == []
    eng.tick(at(2026, 11, 22, 21, 0), open_, None)
    assert titles(n) == ["Garage door is open during quiet hours"]
    eng.tick(at(2026, 11, 22, 21, 10), open_, None)  # before interval
    assert len(titles(n)) == 1
    eng.tick(at(2026, 11, 22, 21, 15), open_, None)
    eng.tick(at(2026, 11, 22, 21, 30), open_, None)
    eng.tick(at(2026, 11, 22, 21, 45), open_, None)
    eng.tick(at(2026, 11, 22, 22, 0), open_, None)
    t = titles(n)
    assert t[1].startswith("Reminder 1 of 2") and t[2].startswith("Reminder 2 of 2")
    assert t[3] == "Garage door still open: no more reminders"
    assert len(t) == 4


def test_quiet_alert_clears_when_closed(engine):
    eng, n, _ = engine
    eng.tick(at(2026, 11, 22, 21, 5), snap(DoorState.OPEN), None)
    eng.tick(at(2026, 11, 22, 21, 6), snap(DoorState.CLOSED), None)
    assert titles(n) == ["Garage door is open during quiet hours", "Garage door closed"]
    assert eng.quiet is None


def test_door_opened_during_quiet_hours_alerts_immediately(engine):
    eng, n, _ = engine
    eng.tick(at(2026, 11, 23, 2, 0), snap(DoorState.CLOSED), None)
    eng.tick(at(2026, 11, 23, 2, 30), snap(DoorState.OPENING), None)
    assert titles(n) == ["Garage door is open during quiet hours"]


def test_stop_time_caps_reminders(engine):
    eng, n, settings = engine
    settings.set_many({"quiet.max_reminders": 50, "quiet.stop_time": "21:20"})
    open_ = snap(DoorState.OPEN)
    for m in (0, 15, 30):
        eng.tick(at(2026, 11, 22, 21, m), open_, None)
    assert titles(n)[-1] == "Garage door still open: no more reminders"


def test_compute_stop_at():
    s, e = at(2026, 11, 22, 21), at(2026, 11, 23, 6)
    assert compute_stop_at(s, e, "") == e
    assert compute_stop_at(s, e, "01:00") == at(2026, 11, 23, 1)
    assert compute_stop_at(s, e, "23:00") == at(2026, 11, 22, 23)
    assert compute_stop_at(s, e, "07:00") == e  # after window end → window end


def test_open_too_long_once(engine):
    eng, n, _ = engine
    s = snap(DoorState.OPEN, at(2026, 11, 22, 10))
    eng.tick(at(2026, 11, 22, 10, 29), s, None)
    eng.tick(at(2026, 11, 22, 10, 30), s, None)
    eng.tick(at(2026, 11, 22, 11, 30), s, None)
    assert len(titles(n, EventType.OPEN_TOO_LONG)) == 1


def test_health_alerts_with_hysteresis(engine):
    eng, n, _ = engine
    closed = snap(DoorState.CLOSED)
    eng.tick(at(2026, 11, 22, 10), closed, Stats(cpu_temp_c=80, throttled_raw=0x50005))
    eng.tick(at(2026, 11, 22, 10, 1), closed, Stats(cpu_temp_c=73, throttled_raw=0x50005))
    eng.tick(at(2026, 11, 22, 10, 2), closed, Stats(cpu_temp_c=81, throttled_raw=0))
    t = titles(n, EventType.HEALTH)
    assert t.count("Garage Pi is overheating") == 1  # 73 is within the 5° hysteresis
    assert t.count("Garage Pi power problem") == 1


def test_notifier_routes_per_user(tmp_path):
    db = Database(tmp_path / "n.sqlite")
    db.migrate()
    store = Store(db)
    now = at(2026, 11, 22)
    a = store.create_user("admin1", "correct-horse-9", "admin", now)
    h = store.create_user("house1", "correct-horse-9", "household", now)
    v = store.create_user("view1", "correct-horse-9", "viewer", now)
    store.update_user(a, discord_user_id="111")
    store.update_user(h, discord_user_id="222")
    store.set_notify_prefs(v, {"door_change"}, use_shared=False, apprise_url="ntfy://ntfy.sh/secret-topic")
    n = Notifier(store, "discord://hook/token")

    sends = n.deliveries(Message(EventType.QUIET_HOURS, "Door open", "body"))
    assert sends == [("discord://hook/token", "Door open", "body\n<@111> <@222>")]

    sends = n.deliveries(Message(EventType.SECURITY, "Locked", ""))
    assert sends == [("discord://hook/token", "Locked", "<@111>")]

    sends = n.deliveries(Message(EventType.DOOR_CHANGE, "Opened", "By pat"))
    assert sends == [("ntfy://ntfy.sh/secret-topic", "Opened", "By pat")]
