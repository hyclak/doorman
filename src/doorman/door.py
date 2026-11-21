"""Door state machine.

The only sensor is a reed switch that knows "closed" vs "not closed". Everything else
(Opening, Closing, Partly open, Unknown) is inferred from the last command and the
configured travel times. ``poll()`` is called ~10x per second by the monitor task.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from doorman.access import OPENING_ACTIONS, Action
from doorman.clock import Clock
from doorman.hardware.base import GpioBackend

log = logging.getLogger(__name__)

DEBOUNCE_S = 0.2
START_TIMEOUT_S = 5.0  # reed must leave "closed" this soon after an open/crack press
CLOSE_GRACE_S = 10.0  # extra time allowed beyond travel_close before "Unknown"
EXTERNAL = "external"


class DoorState(StrEnum):
    CLOSED = "closed"
    OPENING = "opening"
    OPEN = "open"
    CLOSING = "closing"
    PARTLY_OPEN = "partly_open"
    UNKNOWN = "unknown"


STATE_LABELS = {
    DoorState.CLOSED: "Closed",
    DoorState.OPENING: "Opening",
    DoorState.OPEN: "Open",
    DoorState.CLOSING: "Closing",
    DoorState.PARTLY_OPEN: "Partly open",
    DoorState.UNKNOWN: "Check door",
}

ACTIONS_BY_STATE: dict[DoorState, list[Action]] = {
    DoorState.CLOSED: [Action.OPEN, Action.CRACK],
    DoorState.OPEN: [Action.CLOSE],
    DoorState.PARTLY_OPEN: [Action.CLOSE],
    DoorState.OPENING: [],
    DoorState.CLOSING: [],
    DoorState.UNKNOWN: [Action.TOGGLE],
}

ACTION_LABELS = {
    Action.OPEN: "Open",
    Action.CLOSE: "Close",
    Action.CRACK: "Crack open",
    Action.TOGGLE: "Press opener button",
}


class DoorError(Exception):
    pass


@dataclass
class Command:
    action: Action
    mono: float
    actor: str
    source: str
    reed_left: bool = False  # the reed reported "open" after this command


@dataclass(frozen=True)
class DoorEvent:
    kind: str  # opened | closed | state | no_effect
    state: DoorState
    previous: DoorState | None
    actor: str
    source: str
    at: datetime
    message: str = ""


@dataclass(frozen=True)
class Snapshot:
    state: DoorState
    label: str
    reed_closed: bool
    since: datetime
    open_since: datetime | None
    actions: list[Action]
    message: str
    last_actor: str
    last_source: str
    last_change: datetime | None

    @property
    def moving(self) -> bool:
        return self.state in (DoorState.OPENING, DoorState.CLOSING)

    @property
    def is_closed(self) -> bool:
        return self.state == DoorState.CLOSED


Timings = Callable[[str], float]
Listener = Callable[[DoorEvent], None]


class Door:
    def __init__(
        self,
        backend: GpioBackend,
        clock: Clock,
        timings: Timings,
        reed_closed_value: int = 0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.backend = backend
        self.clock = clock
        self._t = timings
        self._closed_value = reed_closed_value
        self._sleep = sleep
        self._listeners: list[Listener] = []
        self._lock = asyncio.Lock()

        self._reed_closed = self._read_closed()
        self._pending: bool | None = None
        self._pending_since = 0.0
        self._cmd: Command | None = None
        self._external_open_mono: float | None = None
        self._message = ""
        self._last_press_mono = float("-inf")
        self._last_actor = ""
        self._last_source = ""
        self._last_change: datetime | None = None
        now = clock.now()
        self._state = DoorState.CLOSED if self._reed_closed else DoorState.OPEN
        self._state_since = now
        self._open_since: datetime | None = None if self._reed_closed else now

    # -- listeners ------------------------------------------------------------------------------

    def add_listener(self, fn: Listener) -> None:
        self._listeners.append(fn)

    def _emit(self, ev: DoorEvent) -> None:
        for fn in self._listeners:
            try:
                fn(ev)
            except Exception:
                log.exception("door listener failed")

    # -- sensing --------------------------------------------------------------------------------

    def _read_closed(self) -> bool:
        return self.backend.read_reed() == self._closed_value

    def poll(self) -> Snapshot:
        now = self.clock.monotonic()
        raw = self._read_closed()
        if raw != self._reed_closed:
            if self._pending is not raw:
                self._pending = raw
                self._pending_since = now
            elif now - self._pending_since >= DEBOUNCE_S:
                self._pending = None
                self._reed_closed = raw
                self._on_reed_change(raw, now)
        else:
            self._pending = None
        self._update_state(now)
        return self.snapshot()

    def _on_reed_change(self, closed: bool, now: float) -> None:
        cmd = self._cmd
        at = self.clock.now()
        self._last_change = at
        if not closed:
            self._open_since = at
            if (
                cmd
                and cmd.action in OPENING_ACTIONS
                and not cmd.reed_left
                and now - cmd.mono < START_TIMEOUT_S + 5
            ):
                cmd.reed_left = True
                actor, source = cmd.actor, cmd.source
            else:
                self._cmd = None
                self._external_open_mono = now
                actor, source = "Wall button or remote", EXTERNAL
            kind = "opened"
        else:
            self._open_since = None
            limit = self._t("door.travel_close_s") + CLOSE_GRACE_S + 30
            if cmd and cmd.action in (Action.CLOSE, Action.TOGGLE) and now - cmd.mono < limit:
                actor, source = cmd.actor, cmd.source
            else:
                actor, source = "Wall button or remote", EXTERNAL
            self._cmd = None
            self._external_open_mono = None
            self._message = ""
            kind = "closed"
        self._last_actor, self._last_source = actor, source
        log.info("door %s by %s (%s)", kind, actor, source)
        self._emit(DoorEvent(kind, self._state, None, actor, source, at))

    def _compute(self, now: float) -> tuple[DoorState, str | None]:
        """Returns (state, new_message or None to keep the current one)."""
        cmd = self._cmd
        if self._reed_closed:
            if cmd and cmd.action in OPENING_ACTIONS and not cmd.reed_left:
                if now - cmd.mono < START_TIMEOUT_S:
                    return DoorState.OPENING, ""
                self._cmd = None
                at = self.clock.now()
                msg = "The last button press didn't move the door."
                self._emit(
                    DoorEvent("no_effect", DoorState.CLOSED, self._state, cmd.actor, cmd.source, at, msg)
                )
                return DoorState.CLOSED, msg
            return DoorState.CLOSED, None
        if cmd:
            age = now - cmd.mono
            if cmd.action == Action.CRACK:
                return DoorState.PARTLY_OPEN, None
            if cmd.action == Action.OPEN:
                return (DoorState.OPENING if age < self._t("door.travel_open_s") else DoorState.OPEN), None
            if cmd.action == Action.CLOSE:
                if age < self._t("door.travel_close_s") + CLOSE_GRACE_S:
                    return DoorState.CLOSING, ""
                return DoorState.UNKNOWN, "The door didn't finish closing. Check it."
            if cmd.action == Action.TOGGLE:
                return DoorState.UNKNOWN, "Button pressed; the direction is unknown. Watch the door."
        if self._external_open_mono is not None and now - self._external_open_mono < self._t(
            "door.travel_open_s"
        ):
            return DoorState.OPENING, None
        if self._state == DoorState.UNKNOWN:
            return DoorState.UNKNOWN, None
        return DoorState.OPEN, None

    def _update_state(self, now: float) -> None:
        state, msg = self._compute(now)
        if msg is not None:
            self._message = msg
        if state != self._state:
            prev = self._state
            self._state = state
            self._state_since = self.clock.now()
            cmd = self._cmd
            actor, source = (cmd.actor, cmd.source) if cmd else (self._last_actor, self._last_source)
            self._emit(DoorEvent("state", state, prev, actor, source, self._state_since, self._message))

    def snapshot(self) -> Snapshot:
        # While a command is in flight (e.g. Closing, before the reed changes), credit its sender.
        cmd = self._cmd
        actor, source = (cmd.actor, cmd.source) if cmd else (self._last_actor, self._last_source)
        return Snapshot(
            state=self._state,
            label=STATE_LABELS[self._state],
            reed_closed=self._reed_closed,
            since=self._state_since,
            open_since=self._open_since,
            actions=list(ACTIONS_BY_STATE[self._state]),
            message=self._message,
            last_actor=actor,
            last_source=source,
            last_change=self._last_change,
        )

    # -- acting ---------------------------------------------------------------------------------

    async def perform(self, action: Action, actor: str, source: str) -> Snapshot:
        async with self._lock:
            snap = self.poll()
            if action not in snap.actions:
                if snap.moving:
                    raise DoorError(f"The door is {snap.label.lower()}. Wait for it to stop.")
                raise DoorError(
                    f"Can't {ACTION_LABELS[action].lower()} while the door is {snap.label.lower()}."
                )
            now = self.clock.monotonic()
            if now - self._last_press_mono < self._t("door.cooldown_s"):
                raise DoorError("The door was just activated. Wait a few seconds.")
            self._cmd = Command(action, now, actor, source)
            self._external_open_mono = None
            self._message = ""
            await self._press()
            if action == Action.CRACK:
                await self._sleep(self._t("door.crack_gap_s"))
                await self._press()
            self._last_press_mono = self.clock.monotonic()
            log.info("relay %s by %s (%s)", action, actor, source)
            return self.poll()

    async def _press(self) -> None:
        self.backend.relay_press()
        try:
            await self._sleep(self._t("door.pulse_s"))
        finally:
            self.backend.relay_release()

    async def test_crack(self, actor: str) -> Snapshot:
        """Admin calibration helper: same as a crack, kept separate for the audit log."""
        return await self.perform(Action.CRACK, actor, "calibration")
