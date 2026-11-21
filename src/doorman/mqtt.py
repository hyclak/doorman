"""Optional MQTT bridge with Home Assistant discovery.

Publishes a garage-door ``cover`` plus sensors. Commands from ``<base>/door/set`` go through
the same access/audit path as everything else (source "mqtt"). If the broker is down, only
Home Assistant is affected; door control through the web UI never depends on it.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Coroutine
from concurrent.futures import Future
from typing import Any

import paho.mqtt.client as mqtt

from doorman import __version__
from doorman.access import Action
from doorman.config import MqttConfig
from doorman.door import DoorState, Snapshot
from doorman.stats import Stats

log = logging.getLogger(__name__)

HA_STATE = {
    DoorState.CLOSED: "closed",
    DoorState.OPENING: "opening",
    DoorState.OPEN: "open",
    DoorState.CLOSING: "closing",
    DoorState.PARTLY_OPEN: "open",
    DoorState.UNKNOWN: "open",
}

Operate = Callable[[Action], Coroutine[Any, Any, str | None]]


def _log_failure(fut: Future[str | None]) -> None:
    if (exc := fut.exception()) is not None:
        log.warning("MQTT command failed: %s", exc)


class MqttBridge:
    def __init__(self, cfg: MqttConfig, operate: Operate, loop: asyncio.AbstractEventLoop) -> None:
        self.cfg = cfg
        self.operate = operate
        self.loop = loop
        b = cfg.base_topic
        self.t_status = f"{b}/status"
        self.t_state = f"{b}/door/state"
        self.t_detail = f"{b}/door/detail"
        self.t_set = f"{b}/door/set"
        self.t_stats = f"{b}/stats"
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="doorman")
        if cfg.username:
            self.client.username_pw_set(cfg.username, cfg.password)
        if cfg.tls:
            self.client.tls_set()
        self.client.will_set(self.t_status, "offline", retain=True)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.reconnect_delay_set(min_delay=5, max_delay=120)
        self._last: Snapshot | None = None

    def start(self) -> None:
        self.client.connect_async(self.cfg.host, self.cfg.port, keepalive=60)
        self.client.loop_start()

    def stop(self) -> None:
        try:
            self.client.publish(self.t_status, "offline", retain=True)
            self.client.disconnect()
        finally:
            self.client.loop_stop()

    def _device(self) -> dict[str, Any]:
        return {
            "identifiers": ["doorman"],
            "name": "Garage door (doorman)",
            "manufacturer": "doorman",
            "sw_version": __version__,
        }

    def _discovery(self) -> list[tuple[str, dict[str, Any]]]:
        p = self.cfg.discovery_prefix
        common = {"availability_topic": self.t_status, "device": self._device()}
        cover: dict[str, Any] = {
            **common,
            "name": "Garage door",
            "unique_id": "doorman_door",
            "device_class": "garage",
            "state_topic": self.t_state,
            "json_attributes_topic": self.t_detail,
        }
        if self.cfg.allow_commands:
            cover.update(
                {
                    "command_topic": self.t_set,
                    "payload_open": "OPEN",
                    "payload_close": "CLOSE",
                    "payload_stop": None,
                }
            )
        sensors = [
            ("cpu_temp", "CPU temperature", "temperature", "°C", "{{ value_json.cpu_temp_c }}"),
            ("wifi_signal", "Wi-Fi signal", "signal_strength", "dBm", "{{ value_json.wifi_signal_dbm }}"),
            ("wifi_quality", "Wi-Fi quality", None, "%", "{{ value_json.wifi_quality }}"),
        ]
        out = [(f"{p}/cover/doorman/door/config", cover)]
        for key, name, dc, unit, tpl in sensors:
            cfg: dict[str, Any] = {
                **common,
                "name": name,
                "unique_id": f"doorman_{key}",
                "state_topic": self.t_stats,
                "value_template": tpl,
                "unit_of_measurement": unit,
                "entity_category": "diagnostic",
            }
            if dc:
                cfg["device_class"] = dc
            out.append((f"{p}/sensor/doorman/{key}/config", cfg))
        return out

    def _on_connect(
        self, client: mqtt.Client, _ud: Any, _flags: Any, reason: Any, _props: Any = None
    ) -> None:
        if getattr(reason, "is_failure", False):
            log.warning("MQTT connect failed: %s", reason)
            return
        log.info("MQTT connected to %s:%s", self.cfg.host, self.cfg.port)
        for topic, payload in self._discovery():
            client.publish(topic, json.dumps(payload), retain=True)
        client.publish(self.t_status, "online", retain=True)
        if self.cfg.allow_commands:
            client.subscribe(self.t_set, qos=1)
        if self._last:
            self.publish_door(self._last)

    def _on_message(self, _client: mqtt.Client, _ud: Any, msg: mqtt.MQTTMessage) -> None:
        payload = msg.payload.decode(errors="replace").strip().upper()
        action = {"OPEN": Action.OPEN, "CLOSE": Action.CLOSE}.get(payload)
        if action is None:
            return
        fut = asyncio.run_coroutine_threadsafe(self.operate(action), self.loop)
        fut.add_done_callback(_log_failure)

    def publish_door(self, snap: Snapshot) -> None:
        self._last = snap
        self.client.publish(self.t_state, HA_STATE[snap.state], retain=True)
        self.client.publish(
            self.t_detail,
            json.dumps(
                {"doorman_state": snap.state.value, "label": snap.label, "last_actor": snap.last_actor}
            ),
            retain=True,
        )

    def publish_stats(self, st: Stats) -> None:
        self.client.publish(self.t_stats, json.dumps(st.as_dict(), default=str), retain=True)
