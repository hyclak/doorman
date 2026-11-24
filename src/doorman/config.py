"""Static configuration: TOML file (non-secret) + environment variables (secrets).

Runtime-tunable values (door timings, alert thresholds) live in the database instead,
see ``doorman.settings``.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path("/etc/doorman/doorman.toml")


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    # Origin users see in their browser (scheme://host[:port]). Used for WebAuthn,
    # guest-link URLs and the Origin check on form posts.
    public_origin: str = "http://localhost:8000"
    # WebAuthn relying-party id: the bare hostname, e.g. "door.example.com".
    rp_id: str = "localhost"
    rp_name: str = "doorman"
    # Secure cookies need HTTPS. Only turn off for local development.
    cookie_secure: bool = True
    # Reverse proxies whose X-Forwarded-For header is trusted (Caddy on the same host).
    trusted_proxies: tuple[str, ...] = ("127.0.0.1", "::1")
    # Enables /dev/* helpers (simulated reed switch). Never on in production.
    dev_mode: bool = False


@dataclass(frozen=True)
class GpioConfig:
    # "lgpio" on the Pi, "mock" for development and tests.
    backend: str = "mock"
    chip: int = 0
    # BCM numbering.
    relay_pin: int = 7
    reed_pin: int = 18
    # Reed level that means "door closed".
    reed_closed_value: int = 0
    # Internal bias for the reed input: "as-is", "none", "up" or "down".
    reed_pull: str = "as-is"
    # How the relay input is driven:
    #   open_drain  - press = drive LOW, release = switch back to input (matches GaragePi)
    #   active_low  - press = LOW, release = HIGH
    #   active_high - press = HIGH, release = LOW
    relay_mode: str = "open_drain"
    # Mock backend only: simulate a door that moves when the relay is pressed.
    simulate_door: bool = True


@dataclass(frozen=True)
class MqttConfig:
    enabled: bool = False
    host: str = "localhost"
    port: int = 1883
    username: str = ""
    password: str = ""  # from DOORMAN_MQTT_PASSWORD
    tls: bool = False
    base_topic: str = "doorman"
    discovery_prefix: str = "homeassistant"
    # Let Home Assistant (or anything allowed to publish to <base>/door/set) operate the door.
    # MQTT commands skip schedules and sign-in, so this is opt-in: turn it on only with broker
    # ACLs that limit who may publish to that topic (and preferably TLS).
    allow_commands: bool = False


@dataclass(frozen=True)
class MetricsConfig:
    enabled: bool = True
    # Kept on loopback; Caddy exposes it on a LAN-only listener restricted to Prometheus.
    host: str = "127.0.0.1"
    port: int = 9101


@dataclass(frozen=True)
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    gpio: GpioConfig = field(default_factory=GpioConfig)
    mqtt: MqttConfig = field(default_factory=MqttConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    db_path: str = "/var/lib/doorman/doorman.sqlite"
    timezone: str = "America/New_York"
    # Treat the clock as NTP-synced without asking timedatectl (development only).
    assume_clock_synced: bool = False
    # Written by the backup timer after a successful push; drives the "backups missing" alert.
    backup_status_file: str = "/var/lib/doorman/last-backup-ok"
    # Secrets (environment only).
    secret_key: str = ""
    shared_discord_webhook: str = ""


def _build(cls: type, data: dict[str, Any]) -> Any:
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unknown {cls.__name__} keys: {', '.join(sorted(unknown))}")
    kwargs = {}
    for k, v in data.items():
        kwargs[k] = tuple(v) if isinstance(v, list) else v
    return cls(**kwargs)


def load_config(path: str | Path | None = None, env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    if path is None:
        path = env.get("DOORMAN_CONFIG") or (DEFAULT_CONFIG_PATH if DEFAULT_CONFIG_PATH.exists() else None)
    data: dict[str, Any] = {}
    if path is not None:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)

    sections = {
        "server": ServerConfig,
        "gpio": GpioConfig,
        "mqtt": MqttConfig,
        "metrics": MetricsConfig,
    }
    kwargs: dict[str, Any] = {}
    for name, cls in sections.items():
        section = data.pop(name, {})
        if name == "mqtt" and env.get("DOORMAN_MQTT_PASSWORD"):
            section = {**section, "password": env["DOORMAN_MQTT_PASSWORD"]}
        kwargs[name] = _build(cls, section)
    for k in ("secret_key", "shared_discord_webhook"):
        if k in data:
            raise ValueError(f"{k} is a secret; set it through the environment, not the config file")
    kwargs.update(data)
    kwargs["secret_key"] = env.get("DOORMAN_SECRET_KEY", "")
    kwargs["shared_discord_webhook"] = env.get("DOORMAN_DISCORD_WEBHOOK", "")
    cfg = _build(Config, kwargs)
    validate(cfg)
    return cfg


def validate(cfg: Config) -> None:
    if cfg.gpio.backend not in ("mock", "lgpio"):
        raise ValueError("gpio.backend must be 'mock' or 'lgpio'")
    if cfg.gpio.relay_mode not in ("open_drain", "active_low", "active_high"):
        raise ValueError("gpio.relay_mode must be open_drain, active_low or active_high")
    if cfg.gpio.reed_pull not in ("as-is", "none", "up", "down"):
        raise ValueError("gpio.reed_pull must be as-is, none, up or down")
    if cfg.gpio.reed_closed_value not in (0, 1):
        raise ValueError("gpio.reed_closed_value must be 0 or 1")
    if not cfg.server.dev_mode and len(cfg.secret_key) < 32:
        raise ValueError("DOORMAN_SECRET_KEY must be set (32+ characters) outside dev_mode")
