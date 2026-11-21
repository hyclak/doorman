"""Prometheus metrics, served on a loopback-only port (Caddy exposes it to Prometheus only)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Info, start_http_server

from doorman import __version__
from doorman.door import DoorState, Snapshot
from doorman.stats import Stats


class Metrics:
    def __init__(self) -> None:
        r = self.registry = CollectorRegistry()
        Info("doorman", "doorman build", registry=r).info({"version": __version__})
        self.door_closed = Gauge("doorman_door_closed", "1 when the reed switch reads closed", registry=r)
        self.door_state = Gauge(
            "doorman_door_state", "Inferred door state (1 = current)", ["state"], registry=r
        )
        self.open_seconds = Gauge("doorman_door_open_seconds", "Seconds the door has been open", registry=r)
        self.actions = Counter(
            "doorman_actions_total", "Door actions performed", ["action", "source"], registry=r
        )
        self.denied = Counter("doorman_actions_denied_total", "Door actions refused", ["source"], registry=r)
        self.changes = Counter(
            "doorman_door_changes_total", "Reed switch transitions", ["kind", "source"], registry=r
        )
        self.logins = Counter("doorman_logins_total", "Sign-in attempts", ["result"], registry=r)
        self.cpu_temp = Gauge("doorman_cpu_temperature_celsius", "SoC temperature", registry=r)
        self.throttled = Gauge("doorman_throttled_flags", "vcgencmd get_throttled bitmask", registry=r)
        self.wifi_quality = Gauge("doorman_wifi_link_quality_percent", "Wi-Fi link quality", registry=r)
        self.wifi_signal = Gauge("doorman_wifi_signal_dbm", "Wi-Fi signal level", registry=r)
        self.clock_synced = Gauge("doorman_clock_synced", "1 when NTP-synchronized", registry=r)
        self.mem_available = Gauge("doorman_memory_available_bytes", "MemAvailable", registry=r)

    def update_door(self, snap: Snapshot, now_ts: float) -> None:
        self.door_closed.set(1 if snap.reed_closed else 0)
        for s in DoorState:
            self.door_state.labels(state=s.value).set(1 if snap.state == s else 0)
        self.open_seconds.set(now_ts - snap.open_since.timestamp() if snap.open_since else 0)

    def update_stats(self, st: Stats) -> None:
        if st.cpu_temp_c is not None:
            self.cpu_temp.set(st.cpu_temp_c)
        if st.throttled_raw is not None:
            self.throttled.set(st.throttled_raw)
        if st.wifi_quality is not None:
            self.wifi_quality.set(st.wifi_quality)
        if st.wifi_signal_dbm is not None:
            self.wifi_signal.set(st.wifi_signal_dbm)
        if st.clock_synced is not None:
            self.clock_synced.set(1 if st.clock_synced else 0)
        if st.mem_available_mb is not None:
            self.mem_available.set(st.mem_available_mb * 1024 * 1024)

    def serve(self, host: str, port: int) -> None:
        start_http_server(port, addr=host, registry=self.registry)
