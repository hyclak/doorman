"""In-memory GPIO with an optional door simulator, for development and tests.

The simulator behaves like a typical opener: a press starts the door moving; a press
while opening stops it; a press while stopped or open closes it; a press while closing
reverses it. Position is computed from the (possibly frozen) clock, so tests are exact.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from doorman.clock import Clock
from doorman.config import GpioConfig


@dataclass
class _Motion:
    direction: int = 0  # +1 opening, -1 closing, 0 stopped
    start_mono: float = 0.0
    start_pos: float = 0.0  # 0 = closed, 1 = fully open


class MockBackend:
    TRAVEL_S = 12.0

    def __init__(self, cfg: GpioConfig, clock: Clock) -> None:
        self.cfg = cfg
        self.clock = clock
        self.simulate = cfg.simulate_door
        self._lock = threading.Lock()
        self._m = _Motion()
        self._manual_reed: int | None = None
        self.relay_active = False
        self.presses: list[float] = []  # monotonic time of each press

    # -- simulator ------------------------------------------------------------------------------

    def position(self) -> float:
        with self._lock:
            return self._position()

    def _position(self) -> float:
        m = self._m
        if m.direction == 0:
            return m.start_pos
        p = m.start_pos + m.direction * (self.clock.monotonic() - m.start_mono) / self.TRAVEL_S
        if p <= 0 or p >= 1:
            p = min(1.0, max(0.0, p))
            self._m = _Motion(0, self.clock.monotonic(), p)
        return p

    def _sim_press(self) -> None:
        pos = self._position()
        now = self.clock.monotonic()
        d = self._m.direction
        if d == 1:
            new_dir = 0  # stop
        elif d == -1:
            new_dir = 1  # reverse
        else:
            new_dir = 1 if pos <= 0.0 else -1
        self._m = _Motion(new_dir, now, pos)

    def set_reed(self, closed: bool | None) -> None:
        """Force the reed reading (None returns control to the simulator)."""
        with self._lock:
            if closed is None:
                self._manual_reed = None
            else:
                self._manual_reed = self.cfg.reed_closed_value if closed else 1 - self.cfg.reed_closed_value
                # Keep the simulator consistent with the forced state.
                self._m = _Motion(0, self.clock.monotonic(), 0.0 if closed else 1.0)

    # -- GpioBackend ----------------------------------------------------------------------------

    def read_reed(self) -> int:
        with self._lock:
            if self._manual_reed is not None:
                return self._manual_reed
            if not self.simulate:
                return self.cfg.reed_closed_value
            closed = self._position() <= 0.0001
            return self.cfg.reed_closed_value if closed else 1 - self.cfg.reed_closed_value

    def relay_press(self) -> None:
        with self._lock:
            self.relay_active = True
            self.presses.append(self.clock.monotonic())
            if self.simulate:
                self._manual_reed = None
                self._sim_press()

    def relay_release(self) -> None:
        with self._lock:
            self.relay_active = False

    def close(self) -> None:
        pass
