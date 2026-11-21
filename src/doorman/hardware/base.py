from __future__ import annotations

from typing import Protocol


class GpioBackend(Protocol):
    def read_reed(self) -> int:
        """Raw level of the reed switch input (0 or 1)."""
        ...

    def relay_press(self) -> None:
        """Start a button press (assert the relay)."""
        ...

    def relay_release(self) -> None:
        """End a button press (release the relay)."""
        ...

    def close(self) -> None: ...
