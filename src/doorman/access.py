"""Access decisions. Pure functions: no I/O, fully unit-tested.

Default deny. Admin and Household may always operate the door; Scheduled users and
guest links only inside an allow window, and only while the clock is NTP-synced.
A guest link that was redeemed inside its window keeps close-only permission until
``late_close_until`` (midnight that day, or the window end if later).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from doorman.schedules import Window, active_occurrence, fmt_date, fmt_time, next_start


class Action(StrEnum):
    OPEN = "open"
    CLOSE = "close"
    CRACK = "crack"
    TOGGLE = "toggle"  # direction unknown (door state Unknown)


OPENING_ACTIONS = frozenset({Action.OPEN, Action.CRACK, Action.TOGGLE})


@dataclass(frozen=True)
class Principal:
    kind: str  # user | link | api | mqtt
    id: int | None
    name: str
    role: str = ""  # admin | household | scheduled | viewer | guest
    disabled: bool = False
    windows: tuple[Window, ...] = ()
    late_close_until: datetime | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_admin(self) -> bool:
        return self.kind == "user" and self.role == "admin" and not self.disabled

    @property
    def time_limited(self) -> bool:
        return self.kind == "link" or (self.kind == "user" and self.role == "scheduled")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.allowed


CLOCK_NOT_SYNCED = (
    "The door controller's clock hasn't synced with the internet yet, so scheduled access "
    "is paused. Try again in a minute."
)


def decide(p: Principal, action: Action, now: datetime, clock_synced: bool) -> Decision:
    if p.disabled:
        return Decision(False, "This account is disabled.")
    if p.kind == "api":
        if "operate" in p.scopes:
            return Decision(True)
        return Decision(False, "This API token is read-only.")
    if p.kind == "mqtt":
        return Decision(True)
    if p.kind == "user" and p.role in ("admin", "household"):
        return Decision(True)
    if p.kind == "user" and p.role == "viewer":
        return Decision(False, "This account can view the door but not operate it.")
    if not p.time_limited:
        return Decision(False, "Not allowed.")

    if not clock_synced:
        return Decision(False, CLOCK_NOT_SYNCED)
    if active_occurrence(p.windows, now):
        return Decision(True)
    if (
        p.kind == "link"
        and action == Action.CLOSE
        and p.late_close_until is not None
        and now < p.late_close_until
    ):
        return Decision(True)
    return Decision(False, outside_window_message(p.windows, now))


def outside_window_message(windows: tuple[Window, ...], now: datetime) -> str:
    nxt = next_start(windows, now)
    if nxt is None:
        return "You don't have access right now, and no upcoming access is scheduled."
    when = fmt_time(nxt.time()) if nxt.date() == now.date() else f"{fmt_date(nxt)} at {fmt_time(nxt.time())}"
    return f"You don't have access right now. Your next access starts {when}."


def can_view(p: Principal, now: datetime, clock_synced: bool) -> Decision:
    """Whether the principal may see door status at all."""
    if p.disabled:
        return Decision(False, "This account is disabled.")
    if p.kind == "link":
        # A redeemed guest session may watch status for as long as the session lives.
        return Decision(True)
    return Decision(True)


def permitted_actions(
    p: Principal, door_actions: list[Action], now: datetime, clock_synced: bool
) -> tuple[list[Action], str]:
    """Filter the actions the door currently offers by what this principal may do.

    Returns (actions, reason-if-none).
    """
    allowed: list[Action] = []
    reason = ""
    for a in door_actions:
        d = decide(p, a, now, clock_synced)
        if d:
            allowed.append(a)
        elif not reason:
            reason = d.reason
    return allowed, reason
