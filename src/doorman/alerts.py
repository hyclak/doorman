"""Alert evaluation, run every few seconds.

* Quiet hours: when a quiet window is active and the door isn't closed, alert once, then
  remind every N minutes until the door closes, the maximum count is reached, or the stop
  time passes (whichever comes first), then send a final "giving up" message. Never auto-closes.
* Open too long (any time of day).
* Health: door state Unknown, CPU overheating, under-voltage/throttling, missed backups.

State is kept in memory; after a restart an ongoing violation simply alerts again.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from doorman.door import DoorState, Snapshot
from doorman.notify import EventType, Notifier
from doorman.schedules import Window, active_occurrence, fmt_time, parse_hhmm
from doorman.settings import Settings
from doorman.stats import Stats

log = logging.getLogger(__name__)

BACKUP_STALE = timedelta(days=3)


@dataclass
class QuietState:
    occurrence_start: datetime
    occurrence_end: datetime
    stop_at: datetime
    sent: int = 0  # first alert + reminders sent
    next_at: datetime | None = None
    gave_up: bool = False


def compute_stop_at(occ_start: datetime, occ_end: datetime, stop_time: str) -> datetime:
    """The first ``stop_time`` after the window starts, capped at the window end."""
    if not stop_time:
        return occ_end
    t = parse_hhmm(stop_time)
    candidate = occ_start.replace(hour=t.hour, minute=t.minute, second=0, microsecond=0)
    if candidate <= occ_start:
        candidate += timedelta(days=1)
    return min(candidate, occ_end)


class AlertEngine:
    def __init__(
        self,
        notifier: Notifier,
        settings: Settings,
        quiet_windows: Callable[[], list[Window]],
        backup_status_file: str = "",
    ) -> None:
        self.notifier = notifier
        self.settings = settings
        self.quiet_windows = quiet_windows
        self.backup_status_file = backup_status_file
        self.quiet: QuietState | None = None
        self._open_too_long_sent = False
        self._unknown_sent = False
        self._hot = False
        self._power_bad = False
        self._backup_alert_day: str | None = None

    # ---- quiet hours --------------------------------------------------------------------------

    def _check_quiet(self, now: datetime, snap: Snapshot) -> None:
        occ = active_occurrence(self.quiet_windows(), now)
        door_open = not snap.is_closed
        q = self.quiet

        if occ is None:
            if q and q.sent and not q.gave_up and door_open:
                self._send_quiet("Quiet hours are over and the garage door is still open.", "")
            self.quiet = None
            return

        if not door_open:
            if q and q.sent:
                self.notifier.publish(
                    EventType.QUIET_HOURS, "Garage door closed", "The quiet-hours alert is cleared."
                )
            self.quiet = None
            return

        if q is None or q.occurrence_start != occ[0]:
            stop = compute_stop_at(occ[0], occ[1], self.settings.get("quiet.stop_time"))
            q = self.quiet = QuietState(occ[0], occ[1], stop, next_at=now)

        if q.gave_up or q.next_at is None or now < q.next_at:
            return

        interval = timedelta(minutes=self.settings.get("quiet.reminder_interval_min"))
        max_reminders = int(self.settings.get("quiet.max_reminders"))
        window_text = f"Quiet hours {fmt_time(occ[0].time())}–{fmt_time(occ[1].time())}"
        if q.sent == 0:
            self._send_quiet("Garage door is open during quiet hours", f"{window_text}. Please close it.")
            q.sent = 1
        elif q.sent <= max_reminders and now < q.stop_at:
            mins = int((now - q.occurrence_start).total_seconds() // 60) if now > q.occurrence_start else 0
            self._send_quiet(
                f"Reminder {q.sent} of {max_reminders}: garage door still open",
                f"{window_text}. Open for at least {mins} minutes of quiet hours.",
            )
            q.sent += 1
        else:
            self._send_quiet(
                "Garage door still open: no more reminders",
                f"{window_text}. Stopped reminding after {q.sent} messages. The door is still open.",
            )
            q.gave_up = True
            q.next_at = None
            return
        q.next_at = now + interval

    def _send_quiet(self, title: str, body: str) -> None:
        self.notifier.publish(EventType.QUIET_HOURS, title, body)

    # ---- other evaluators ---------------------------------------------------------------------

    def _check_open_too_long(self, now: datetime, snap: Snapshot) -> None:
        limit = int(self.settings.get("alerts.open_too_long_min"))
        if snap.is_closed or not snap.open_since or limit <= 0:
            self._open_too_long_sent = False
            return
        if not self._open_too_long_sent and now - snap.open_since >= timedelta(minutes=limit):
            self._open_too_long_sent = True
            self.notifier.publish(
                EventType.OPEN_TOO_LONG,
                f"Garage door open for {limit}+ minutes",
                f"Opened by {snap.last_actor or 'unknown'}.",
            )

    def _check_unknown(self, snap: Snapshot) -> None:
        if snap.state == DoorState.UNKNOWN:
            if not self._unknown_sent:
                self._unknown_sent = True
                self.notifier.publish(EventType.HEALTH, "Check the garage door", snap.message)
        else:
            self._unknown_sent = False

    def _check_stats(self, stats: Stats | None) -> None:
        if stats is None:
            return
        limit = float(self.settings.get("alerts.cpu_temp_c"))
        if stats.cpu_temp_c is not None:
            if not self._hot and stats.cpu_temp_c >= limit:
                self._hot = True
                self.notifier.publish(
                    EventType.HEALTH, "Garage Pi is overheating", f"CPU at {stats.cpu_temp_c:.0f} °C."
                )
            elif self._hot and stats.cpu_temp_c < limit - 5:
                self._hot = False
        bad = stats.under_voltage_now or stats.throttled_now
        if bad and not self._power_bad:
            self._power_bad = True
            self.notifier.publish(
                EventType.HEALTH,
                "Garage Pi power problem",
                ", ".join(stats.throttle_flags) + ". Check the power supply.",
            )
        elif not bad:
            self._power_bad = False

    def _check_backup(self, now: datetime) -> None:
        if not self.backup_status_file or not os.path.exists(os.path.dirname(self.backup_status_file) or "."):
            return
        try:
            mtime = os.path.getmtime(self.backup_status_file)
        except OSError:
            return  # no backup has ever run (fresh install); don't nag
        age = now.timestamp() - mtime
        today = now.date().isoformat()
        if age > BACKUP_STALE.total_seconds() and self._backup_alert_day != today:
            self._backup_alert_day = today
            self.notifier.publish(
                EventType.HEALTH,
                "doorman backups are failing",
                f"Last successful backup was {int(age // 86400)} days ago. Is the NAS reachable?",
            )

    def tick(self, now: datetime, snap: Snapshot, stats: Stats | None) -> None:
        for fn in (
            lambda: self._check_quiet(now, snap),
            lambda: self._check_open_too_long(now, snap),
            lambda: self._check_unknown(snap),
            lambda: self._check_stats(stats),
            lambda: self._check_backup(now),
        ):
            try:
                fn()
            except Exception:
                log.exception("alert evaluator failed")
