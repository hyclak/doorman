"""Live Pi stats gathered with no extra hardware. Every reading degrades to None off-Pi."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass

THROTTLE_BITS = {
    0: "Under-voltage now",
    1: "CPU frequency capped now",
    2: "Throttled now",
    3: "Soft temperature limit now",
    16: "Under-voltage has occurred",
    17: "Frequency capping has occurred",
    18: "Throttling has occurred",
    19: "Soft temperature limit has occurred",
}


@dataclass(frozen=True)
class Stats:
    cpu_temp_c: float | None = None
    throttled_raw: int | None = None
    uptime_s: float | None = None
    load_1m: float | None = None
    mem_total_mb: float | None = None
    mem_available_mb: float | None = None
    disk_total_gb: float | None = None
    disk_free_gb: float | None = None
    wifi_iface: str | None = None
    wifi_quality: float | None = None  # link quality as a percentage
    wifi_signal_dbm: float | None = None
    clock_synced: bool | None = None
    sampled_at: float = 0.0

    @property
    def throttle_flags(self) -> list[str]:
        if self.throttled_raw is None:
            return []
        return [label for bit, label in THROTTLE_BITS.items() if self.throttled_raw & (1 << bit)]

    @property
    def under_voltage_now(self) -> bool:
        return bool(self.throttled_raw and self.throttled_raw & 0x1)

    @property
    def throttled_now(self) -> bool:
        return bool(self.throttled_raw and self.throttled_raw & 0xE)

    def as_dict(self) -> dict[str, object]:
        d = asdict(self)
        d["throttle_flags"] = self.throttle_flags
        return d


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def cpu_temp() -> float | None:
    raw = _read("/sys/class/thermal/thermal_zone0/temp")
    return round(int(raw) / 1000, 1) if raw and raw.strip().isdigit() else None


def throttled() -> int | None:
    vc = shutil.which("vcgencmd")
    if not vc:
        return None
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, resolved binary
            [vc, "get_throttled"], capture_output=True, text=True, timeout=3, check=False
        ).stdout
        return int(out.strip().split("=")[1], 16)
    except (OSError, subprocess.SubprocessError, IndexError, ValueError):
        return None


def meminfo() -> tuple[float | None, float | None]:
    raw = _read("/proc/meminfo")
    if not raw:
        return None, None
    vals = {}
    for line in raw.splitlines():
        k, _, rest = line.partition(":")
        vals[k] = int(rest.split()[0]) / 1024 if rest.strip() else 0
    return vals.get("MemTotal"), vals.get("MemAvailable")


def wifi() -> tuple[str | None, float | None, float | None]:
    raw = _read("/proc/net/wireless")
    if not raw:
        return None, None, None
    for line in raw.splitlines()[2:]:
        parts = line.split()
        if len(parts) >= 4:
            iface = parts[0].rstrip(":")
            quality = float(parts[2].rstrip("."))
            signal = float(parts[3].rstrip("."))
            return iface, round(quality / 70 * 100), signal
    return None, None, None


def sample(clock_synced: bool | None = None, disk_path: str = "/") -> Stats:
    up = _read("/proc/uptime")
    total, avail = meminfo()
    disk_total: float | None
    disk_free: float | None
    try:
        du = shutil.disk_usage(disk_path)
        disk_total, disk_free = du.total / 1e9, du.free / 1e9
    except OSError:
        disk_total = disk_free = None
    iface, quality, signal = wifi()
    try:
        load = os.getloadavg()[0]
    except OSError:
        load = None
    return Stats(
        cpu_temp_c=cpu_temp(),
        throttled_raw=throttled(),
        uptime_s=float(up.split()[0]) if up else None,
        load_1m=round(load, 2) if load is not None else None,
        mem_total_mb=round(total) if total else None,
        mem_available_mb=round(avail) if avail else None,
        disk_total_gb=round(disk_total, 1) if disk_total else None,
        disk_free_gb=round(disk_free, 1) if disk_free else None,
        wifi_iface=iface,
        wifi_quality=quality,
        wifi_signal_dbm=signal,
        clock_synced=clock_synced,
        sampled_at=time.time(),
    )


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"
