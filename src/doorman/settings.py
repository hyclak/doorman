"""Runtime settings editable from the admin UI, stored as JSON in the settings table."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Any

from doorman.db import Database


@dataclass(frozen=True)
class SettingDef:
    key: str
    default: Any
    label: str
    help: str = ""
    minimum: float | None = None
    maximum: float | None = None
    kind: str = "number"  # number | time | bool


SETTINGS: tuple[SettingDef, ...] = (
    # Door
    SettingDef("door.travel_open_s", 15.0, "Door opening time (s)", "How long a full open takes.", 3, 60),
    SettingDef("door.travel_close_s", 15.0, "Door closing time (s)", "How long a full close takes.", 3, 60),
    SettingDef("door.pulse_s", 0.5, "Button press length (s)", "How long the relay is held.", 0.1, 2),
    SettingDef(
        "door.crack_gap_s",
        0.5,
        "Crack: pause between presses (s)",
        "Time from releasing the first press to starting the second. Longer = wider gap.",
        0.1,
        5,
    ),
    SettingDef("door.cooldown_s", 3.0, "Cooldown between actions (s)", "", 0, 30),
    # Quiet hours
    SettingDef("quiet.reminder_interval_min", 15, "Reminder every (minutes)", "", 1, 240),
    SettingDef("quiet.max_reminders", 8, "Maximum reminders", "After the first alert.", 0, 100),
    SettingDef(
        "quiet.stop_time",
        "",
        "Stop reminding at",
        "Optional time of day, e.g. 01:00. Empty = window end.",
        kind="time",
    ),
    # Other alerts
    SettingDef("alerts.open_too_long_min", 30, "Open too long after (minutes)", "0 turns it off.", 0, 1440),
    SettingDef("alerts.cpu_temp_c", 75, "CPU temperature alert (°C)", "", 50, 90),
)
DEFAULTS = {s.key: s.default for s in SETTINGS}
BY_KEY = {s.key: s for s in SETTINGS}


class Settings:
    def __init__(self, db: Database) -> None:
        self._db = db
        self._lock = threading.Lock()
        self._cache: dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        values = dict(DEFAULTS)
        for row in self._db.query("SELECT key, value FROM settings"):
            if row["key"] in values:
                values[row["key"]] = json.loads(row["value"])
        with self._lock:
            self._cache = values

    def get(self, key: str) -> Any:
        with self._lock:
            return self._cache[key]

    def all(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._cache)

    def set_many(self, values: dict[str, Any]) -> None:
        clean = {k: coerce(k, v) for k, v in values.items()}
        with self._db.transaction() as conn:
            for k, v in clean.items():
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (k, json.dumps(v)),
                )
        self.reload()


def coerce(key: str, value: Any) -> Any:
    d = BY_KEY.get(key)
    if d is None:
        raise KeyError(key)
    if d.kind == "time":
        v = str(value).strip()
        if v:
            hh, mm = v.split(":")
            if not (0 <= int(hh) < 24 and 0 <= int(mm) < 60):
                raise ValueError(f"{d.label}: invalid time")
            v = f"{int(hh):02d}:{int(mm):02d}"
        return v
    if d.kind == "bool":
        return bool(value)
    num = float(value)
    if d.minimum is not None and num < d.minimum:
        raise ValueError(f"{d.label}: must be at least {d.minimum:g}")
    if d.maximum is not None and num > d.maximum:
        raise ValueError(f"{d.label}: must be at most {d.maximum:g}")
    return int(num) if isinstance(d.default, int) else num
