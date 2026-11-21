"""Real GPIO through lgpio (Raspberry Pi OS package python3-lgpio, kernel GPIO character device)."""

from __future__ import annotations

import contextlib
import threading

import lgpio

from doorman.config import GpioConfig

_PULL = {
    "as-is": 0,
    "none": lgpio.SET_PULL_NONE,
    "up": lgpio.SET_PULL_UP,
    "down": lgpio.SET_PULL_DOWN,
}


class LgpioBackend:
    def __init__(self, cfg: GpioConfig) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self._h = lgpio.gpiochip_open(cfg.chip)
        lgpio.gpio_claim_input(self._h, cfg.reed_pin, _PULL[cfg.reed_pull])
        self._relay_claimed_output = False
        self.relay_release()

    def read_reed(self) -> int:
        with self._lock:
            return int(lgpio.gpio_read(self._h, self.cfg.reed_pin))

    def relay_press(self) -> None:
        with self._lock:
            mode = self.cfg.relay_mode
            level = 1 if mode == "active_high" else 0
            if mode == "open_drain":
                self._free_relay()
                lgpio.gpio_claim_output(self._h, self.cfg.relay_pin, level)
                self._relay_claimed_output = True
            else:
                lgpio.gpio_write(self._h, self.cfg.relay_pin, level)

    def relay_release(self) -> None:
        with self._lock:
            mode = self.cfg.relay_mode
            if mode == "open_drain":
                # Back to a high-impedance input, leaving bias as the firmware set it
                # (BCM 0-8 default to pull-up), exactly like GaragePi's GPIO.setup(IN).
                self._free_relay()
                lgpio.gpio_claim_input(self._h, self.cfg.relay_pin, 0)
            else:
                idle = 0 if mode == "active_high" else 1
                if not self._relay_claimed_output:
                    lgpio.gpio_claim_output(self._h, self.cfg.relay_pin, idle)
                    self._relay_claimed_output = True
                else:
                    lgpio.gpio_write(self._h, self.cfg.relay_pin, idle)

    def _free_relay(self) -> None:
        with contextlib.suppress(lgpio.error):
            lgpio.gpio_free(self._h, self.cfg.relay_pin)
        self._relay_claimed_output = False

    def close(self) -> None:
        try:
            self.relay_release()
        finally:
            lgpio.gpiochip_close(self._h)
