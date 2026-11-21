"""Push notifications through Apprise with per-user preferences.

Each user picks event types and destinations: the shared Discord webhook (one message per
event, mentioning everyone subscribed who set a Discord user ID) and/or a personal Apprise
URL. Sending happens on a background queue so it can never block door control.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from doorman.store import Store

log = logging.getLogger(__name__)


class EventType(StrEnum):
    QUIET_HOURS = "quiet_hours"
    OPEN_TOO_LONG = "open_too_long"
    DOOR_CHANGE = "door_change"
    GUEST_USE = "guest_use"
    SECURITY = "security"
    HEALTH = "health"


EVENT_INFO: dict[EventType, tuple[str, str]] = {
    EventType.QUIET_HOURS: ("Quiet hours", "Door open when it should be closed, with reminders."),
    EventType.OPEN_TOO_LONG: ("Open too long", "Door has been open longer than the set limit."),
    EventType.DOOR_CHANGE: ("Every open/close", "Each time the door opens or closes, and who did it."),
    EventType.GUEST_USE: ("Guest use", "A guest link or scheduled account operates the door."),
    EventType.SECURITY: ("Security", "Lockouts after failed sign-ins or PINs, and admin sign-ins."),
    EventType.HEALTH: (
        "Health",
        "Restarts, overheating, power problems, door state unknown, missed backups.",
    ),
}

DEFAULT_EVENTS: dict[str, set[str]] = {
    "admin": {
        e.value
        for e in (
            EventType.QUIET_HOURS,
            EventType.OPEN_TOO_LONG,
            EventType.SECURITY,
            EventType.HEALTH,
            EventType.GUEST_USE,
        )
    },
    "household": {EventType.QUIET_HOURS.value, EventType.OPEN_TOO_LONG.value},
    "scheduled": set(),
    "viewer": set(),
}


@dataclass(frozen=True)
class Message:
    event: EventType
    title: str
    body: str


Sender = Callable[[str, str, str], bool]


def apprise_sender(url: str, title: str, body: str) -> bool:
    import apprise  # imported lazily: slow to import on a Pi Zero

    ap = apprise.Apprise()
    if not ap.add(url):
        log.warning("invalid notification URL (scheme %s)", url.split("://", 1)[0])
        return False
    return bool(ap.notify(title=title, body=body))


class Notifier:
    def __init__(self, store: Store, shared_webhook: str, sender: Sender | None = None) -> None:
        self.store = store
        self.shared_webhook = shared_webhook
        self.sender = sender or apprise_sender
        self._queue: asyncio.Queue[Message] | None = None
        self.sent: list[tuple[str, str, str]] = []  # recent deliveries, for the admin page/tests

    def publish(self, event: EventType, title: str, body: str = "") -> None:
        log.info("notify %s: %s %s", event.value, title, body)
        if self._queue is None:
            return
        msg = Message(event, title, body)
        try:
            self._queue.put_nowait(msg)
        except asyncio.QueueFull:
            log.warning("notification queue full; dropping oldest")
            self._queue.get_nowait()
            self._queue.put_nowait(msg)

    def deliveries(self, msg: Message) -> list[tuple[str, str, str]]:
        """Resolve recipients into (url, title, body) sends."""
        mentions: list[str] = []
        shared_wanted = False
        personal: dict[str, None] = {}
        for u in self.store.users():
            if u["disabled"]:
                continue
            prefs = self.store.notify_prefs(u["id"])
            events = set(prefs["events"].split(",")) if prefs else DEFAULT_EVENTS[u["role"]]
            if msg.event.value not in events:
                continue
            use_shared = bool(prefs["use_shared"]) if prefs else True
            if use_shared and self.shared_webhook:
                shared_wanted = True
                if u["discord_user_id"]:
                    mentions.append(f"<@{u['discord_user_id']}>")
            if prefs and prefs["apprise_url"]:
                personal[prefs["apprise_url"]] = None
        out: list[tuple[str, str, str]] = []
        if shared_wanted:
            body = msg.body
            if mentions:
                body = (body + "\n" if body else "") + " ".join(dict.fromkeys(mentions))
            out.append((self.shared_webhook, msg.title, body))
        for url in personal:
            if url != self.shared_webhook:
                out.append((url, msg.title, msg.body))
        return out

    async def run(self) -> None:
        self._queue = asyncio.Queue(maxsize=200)
        while True:
            msg = await self._queue.get()
            try:
                sends = await asyncio.to_thread(self.deliveries, msg)
                for url, title, body in sends:
                    await self._send_with_retry(url, title, body)
            except Exception:
                log.exception("notification delivery failed")

    async def _send_with_retry(self, url: str, title: str, body: str) -> None:
        for attempt in range(3):
            try:
                if await asyncio.to_thread(self.sender, url, title, body):
                    self.sent = [*self.sent[-49:], (url.split("://", 1)[0], title, body)]
                    return
            except Exception:
                log.exception("notification send error")
            await asyncio.sleep(5 * (attempt + 1))
        log.warning("gave up sending notification %r", title)

    async def send_test(self, url: str, title: str, body: str) -> bool:
        return await asyncio.to_thread(self.sender, url, title, body)


def group_by_url(sends: list[tuple[str, str, str]]) -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for url, t, b in sends:
        out[url].append((t, b))
    return out
