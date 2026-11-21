"""Service container: wires config, database, door, alerts, notifications, metrics and MQTT,
and owns the background tasks. The web layer talks only to this."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import Awaitable, Callable
from datetime import timedelta

from doorman import sdnotify
from doorman import stats as stats_mod
from doorman.access import Action, Principal, decide
from doorman.alerts import AlertEngine
from doorman.auth.passkeys import Passkeys
from doorman.clock import Clock
from doorman.config import Config
from doorman.db import Database
from doorman.door import ACTION_LABELS, EXTERNAL, Door, DoorEvent, Snapshot
from doorman.hardware import GpioBackend, make_backend
from doorman.metrics import Metrics
from doorman.notify import EventType, Notifier, Sender
from doorman.settings import Settings
from doorman.stats import Stats
from doorman.store import Session, Store

log = logging.getLogger(__name__)

SOURCE_LABELS = {
    "user": "web",
    "link": "guest link",
    "api": "API",
    "mqtt": "Home Assistant",
    EXTERNAL: "wall button or remote",
    "calibration": "calibration test",
}


class AccessDenied(Exception):
    pass


class Core:
    def __init__(
        self,
        cfg: Config,
        clock: Clock | None = None,
        backend: GpioBackend | None = None,
        sender: Sender | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self.cfg = cfg
        self.clock = clock or Clock(cfg.timezone, cfg.assume_clock_synced)
        self.db = Database(cfg.db_path)
        self.db.migrate()
        self.store = Store(self.db)
        self.settings = Settings(self.db)
        self.backend = backend or make_backend(cfg.gpio, self.clock)
        self.door = Door(
            self.backend,
            self.clock,
            self.settings.get,
            cfg.gpio.reed_closed_value,
            sleep=sleep or asyncio.sleep,
        )
        self.notifier = Notifier(self.store, cfg.shared_discord_webhook, sender)
        self.alerts = AlertEngine(
            self.notifier, self.settings, lambda: self.store.windows("quiet"), cfg.backup_status_file
        )
        self.metrics = Metrics()
        self.passkeys = Passkeys(cfg.server.rp_id, cfg.server.rp_name, cfg.server.public_origin)
        self.stats: Stats | None = None
        self.mqtt = None
        self._tasks: list[asyncio.Task[None]] = []
        self.door.add_listener(self._on_door_event)

    # ---- principals ---------------------------------------------------------------------------

    def principal_for_user(self, u: sqlite3.Row) -> Principal:
        windows = tuple(self.store.windows("user", u["id"])) if u["role"] == "scheduled" else ()
        return Principal(
            "user",
            u["id"],
            u["display_name"] or u["username"],
            role=u["role"],
            disabled=bool(u["disabled"]),
            windows=windows,
        )

    def principal_for_link(self, link: sqlite3.Row, session: Session) -> Principal:
        who = link["display_name"] or link["username"]
        name = f"{who} ({link['label']})" if link["label"] else who
        return Principal(
            "link",
            link["id"],
            name,
            role="guest",
            disabled=bool(link["revoked"] or link["user_disabled"]),
            windows=tuple(self.store.windows("link", link["id"])),
            late_close_until=session.late_close_until,
        )

    @staticmethod
    def principal_for_token(row: sqlite3.Row) -> Principal:
        return Principal("api", row["id"], f"API: {row['name']}", scopes=frozenset(row["scopes"].split(",")))

    # ---- door operation (the one path every source goes through) ------------------------------

    async def operate(self, p: Principal, action: Action, ip: str = "") -> Snapshot:
        now = self.clock.now()
        d = decide(p, action, now, self.clock.synced())
        if not d:
            self.metrics.denied.labels(source=p.kind).inc()
            self.store.audit(
                now, p.kind, p.name, f"door.{action.value}.denied", {"reason": d.reason}, p.id, ip
            )
            raise AccessDenied(d.reason)
        snap = await self.door.perform(action, p.name, p.kind)
        self.metrics.actions.labels(action=action.value, source=p.kind).inc()
        self.store.audit(self.clock.now(), p.kind, p.name, f"door.{action.value}", "", p.id, ip)
        if p.time_limited:
            self.notifier.publish(
                EventType.GUEST_USE,
                f"{p.name}: {ACTION_LABELS[action].lower()}",
                f"Door is {snap.label.lower()}.",
            )
        return snap

    def _on_door_event(self, ev: DoorEvent) -> None:
        if ev.kind in ("opened", "closed"):
            via = SOURCE_LABELS.get(ev.source, ev.source)
            who = ev.actor if ev.source != EXTERNAL else "the wall button or a remote"
            self.metrics.changes.labels(kind=ev.kind, source=ev.source).inc()
            self.store.audit(ev.at, ev.source, ev.actor, f"door.{ev.kind}", {"via": via})
            self.notifier.publish(EventType.DOOR_CHANGE, f"Garage door {ev.kind}", f"By {who} ({via}).")
        elif ev.kind == "no_effect":
            self.store.audit(ev.at, ev.source, ev.actor, "door.no_effect", ev.message)
            self.notifier.publish(EventType.HEALTH, "Garage door didn't move", ev.message)
        if self.mqtt is not None:
            with contextlib.suppress(Exception):
                self.mqtt.publish_door(self.door.snapshot())

    # ---- background tasks ---------------------------------------------------------------------

    async def _monitor(self) -> None:
        # The systemd watchdog is fed from this loop, so a stalled door monitor gets the service
        # restarted. Polls that raise don't feed it: a reed read that keeps failing restarts too.
        ping_every = sdnotify.watchdog_interval_s()
        last_ping = float("-inf")
        i = 0
        while True:
            try:
                snap = self.door.poll()
                if i % 10 == 0:
                    self.metrics.update_door(snap, self.clock.now().timestamp())
                if ping_every is not None and self.clock.monotonic() - last_ping >= ping_every:
                    sdnotify.notify("WATCHDOG=1")
                    last_ping = self.clock.monotonic()
            except Exception:
                log.exception("door poll failed")
            i += 1
            await asyncio.sleep(0.1)

    async def _stats_loop(self) -> None:
        while True:
            try:
                st = await asyncio.to_thread(stats_mod.sample, self.clock.synced())
                self.stats = st
                self.metrics.update_stats(st)
                if self.mqtt is not None:
                    self.mqtt.publish_stats(st)
            except Exception:
                log.exception("stats sampling failed")
            await asyncio.sleep(15)

    async def _alerts_loop(self) -> None:
        await asyncio.sleep(5)  # let the reed debounce and stats arrive first
        while True:
            self.alerts.tick(self.clock.now(), self.door.snapshot(), self.stats)
            await asyncio.sleep(5)

    async def _housekeeping(self) -> None:
        while True:
            try:
                now = self.clock.now()
                self.store.purge_expired_sessions(now)
                if pruned := self.store.prune_audit(now):
                    log.info("pruned %d audit rows", pruned)
            except Exception:
                log.exception("housekeeping failed")
            await asyncio.sleep(timedelta(hours=6).total_seconds())

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._tasks = [
            asyncio.create_task(self.notifier.run(), name="notifier"),
            asyncio.create_task(self._monitor(), name="door-monitor"),
            asyncio.create_task(self._stats_loop(), name="stats"),
            asyncio.create_task(self._alerts_loop(), name="alerts"),
            asyncio.create_task(self._housekeeping(), name="housekeeping"),
        ]
        if self.cfg.metrics.enabled:
            try:
                self.metrics.serve(self.cfg.metrics.host, self.cfg.metrics.port)
            except OSError as e:
                log.warning("metrics listener not started: %s", e)
        if self.cfg.mqtt.enabled:
            from doorman.mqtt import MqttBridge

            mqtt_principal = Principal("mqtt", None, "Home Assistant (MQTT)")

            async def via_mqtt(action: Action) -> str | None:
                await self.operate(mqtt_principal, action)
                return None

            self.mqtt = MqttBridge(self.cfg.mqtt, via_mqtt, loop)  # type: ignore[assignment]
            self.mqtt.start()  # type: ignore[attr-defined]
        await asyncio.sleep(0)
        up = stats_mod.sample().uptime_s
        what = "Garage Pi rebooted" if up is not None and up < 300 else "doorman restarted"
        self.store.audit(self.clock.now(), "system", "doorman", "system.start", {"uptime_s": up})
        self.notifier.publish(EventType.HEALTH, what, f"Door is {self.door.snapshot().label.lower()}.")
        sdnotify.notify("READY=1")

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        if self.mqtt is not None:
            self.mqtt.stop()
        self.backend.relay_release()
        self.backend.close()
