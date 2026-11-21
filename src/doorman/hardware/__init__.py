"""GPIO backends. ``make_backend`` picks lgpio on the Pi or the mock for dev/tests."""

from __future__ import annotations

from doorman.clock import Clock
from doorman.config import GpioConfig
from doorman.hardware.base import GpioBackend


def make_backend(cfg: GpioConfig, clock: Clock) -> GpioBackend:
    if cfg.backend == "lgpio":
        from doorman.hardware.lgpio_backend import LgpioBackend

        return LgpioBackend(cfg)
    from doorman.hardware.mock import MockBackend

    return MockBackend(cfg, clock)


__all__ = ["GpioBackend", "make_backend"]
