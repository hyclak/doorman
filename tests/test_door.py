import asyncio

import pytest

from doorman.access import Action
from doorman.config import GpioConfig
from doorman.door import Door, DoorError, DoorState
from doorman.hardware.mock import MockBackend
from doorman.settings import DEFAULTS


def make(clock, simulate=True):
    backend = MockBackend(GpioConfig(simulate_door=simulate), clock)
    timings = dict(DEFAULTS)

    async def fake_sleep(s):
        clock.advance(s)

    door = Door(backend, clock, lambda k: timings[k], sleep=fake_sleep)
    events = []
    door.add_listener(events.append)
    return door, backend, events, timings


def run(coro):
    return asyncio.run(coro)


def settle(door, clock, seconds, step=0.1):
    for _ in range(int(seconds / step)):
        clock.advance(step)
        door.poll()
    return door.poll()


def test_starts_closed_with_open_and_crack(clock):
    door, *_ = make(clock)
    snap = door.poll()
    assert snap.state == DoorState.CLOSED
    assert snap.actions == [Action.OPEN, Action.CRACK]


def test_open_then_close_cycle(clock):
    door, backend, events, _ = make(clock)
    snap = run(door.perform(Action.OPEN, "alice", "user"))
    assert snap.state == DoorState.OPENING
    assert len(backend.presses) == 1
    snap = settle(door, clock, 20)
    assert snap.state == DoorState.OPEN
    assert [e.kind for e in events if e.kind in ("opened", "closed")] == ["opened"]
    assert all(e.actor == "alice" for e in events)

    clock.advance(5)
    snap = run(door.perform(Action.CLOSE, "alice", "user"))
    assert snap.state == DoorState.CLOSING
    snap = settle(door, clock, 15)
    assert snap.state == DoorState.CLOSED
    closed = next(e for e in events if e.kind == "closed")
    assert closed.actor == "alice" and closed.source == "user"


def test_crack_presses_twice_and_is_partly_open(clock):
    door, backend, _, timings = make(clock)
    run(door.perform(Action.CRACK, "bob", "user"))
    assert len(backend.presses) == 2
    gap = backend.presses[1] - backend.presses[0]
    assert gap == pytest.approx(timings["door.pulse_s"] + timings["door.crack_gap_s"])
    snap = settle(door, clock, 2)
    assert snap.state == DoorState.PARTLY_OPEN
    assert snap.actions == [Action.CLOSE]
    assert 0 < backend.position() < 1


def test_crack_not_allowed_when_open(clock):
    door, backend, *_ = make(clock)
    backend.set_reed(closed=False)
    settle(door, clock, 1)
    with pytest.raises(DoorError):
        run(door.perform(Action.CRACK, "bob", "user"))


def test_cooldown(clock):
    door, backend, *_ = make(clock, simulate=False)
    backend.set_reed(closed=False)
    assert settle(door, clock, 20).state == DoorState.OPEN
    run(door.perform(Action.CLOSE, "a", "user"))
    # Door didn't move (no simulator), state is Closing; force back to Open to test cooldown alone.
    door._cmd = None
    door._state = DoorState.OPEN
    with pytest.raises(DoorError, match="just activated"):
        run(door.perform(Action.CLOSE, "a", "user"))


def test_press_with_no_effect_reports_message(clock):
    door, _backend, events, _ = make(clock, simulate=False)
    run(door.perform(Action.OPEN, "a", "user"))
    snap = settle(door, clock, 6)
    assert snap.state == DoorState.CLOSED
    assert "didn't move" in snap.message
    assert any(e.kind == "no_effect" for e in events)


def test_external_open_is_attributed_to_wall_button(clock):
    door, backend, events, _ = make(clock)
    backend.relay_press()  # someone used the remote (simulator moves, doorman didn't command it)
    backend.relay_release()
    snap = settle(door, clock, 1)
    assert snap.state == DoorState.OPENING
    opened = next(e for e in events if e.kind == "opened")
    assert opened.source == "external"
    assert settle(door, clock, 20).state == DoorState.OPEN


def test_close_that_never_finishes_goes_unknown(clock):
    door, backend, _events, _ = make(clock, simulate=False)
    backend.set_reed(closed=False)
    settle(door, clock, 20)
    run(door.perform(Action.CLOSE, "a", "user"))
    snap = settle(door, clock, 30)
    assert snap.state == DoorState.UNKNOWN
    assert snap.actions == [Action.TOGGLE]
    backend.set_reed(closed=True)
    assert settle(door, clock, 1).state == DoorState.CLOSED


def test_debounce_ignores_glitch(clock):
    door, backend, events, _ = make(clock, simulate=False)
    backend.set_reed(closed=False)
    clock.advance(0.1)
    door.poll()
    backend.set_reed(closed=True)
    settle(door, clock, 1)
    assert not [e for e in events if e.kind == "opened"]


def test_closing_credits_the_person_who_pressed_close(clock):
    door, backend, _events, _ = make(clock)
    backend.relay_press()  # wall remote opens the door
    backend.relay_release()
    assert settle(door, clock, 20).last_actor == "Wall button or remote"
    run(door.perform(Action.CLOSE, "Cleaner", "link"))
    snap = settle(door, clock, 1)
    assert snap.state == DoorState.CLOSING
    assert (snap.last_actor, snap.last_source) == ("Cleaner", "link")
