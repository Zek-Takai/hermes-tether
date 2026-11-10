"""Settings, identity and the long-lived services, shared by the gateway process and the CLI."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any, Callable

from .identity import HermesSecretStore, Identity, load_or_create
from .store import data_dir

DEFAULT_PORT = 9130          # link; pairing uses the next port, only while `hermes tether pair` runs


@dataclass
class Settings:
    roles: set
    name: str
    listen_host: str
    listen_port: int
    grant_idle_minutes: float
    consent_timeout_seconds: float

    @property
    def pairing_port(self) -> int:
        return self.listen_port + 1


def read_settings(get: Callable[[str, Any], Any]) -> Settings:
    raw = str(get("role", "off") or "off").lower()
    roles = {r.strip() for r in raw.split(",") if r.strip() in {"host", "device"}}
    listen = str(get("listen", "") or "")
    host, _, port = listen.rpartition(":") if ":" in listen else (listen, "", "")
    return Settings(roles=roles, name=str(get("name", "") or socket.gethostname().split(".")[0]).lower(),
                    listen_host=host or "127.0.0.1", listen_port=int(port or DEFAULT_PORT),
                    grant_idle_minutes=float(get("grant_idle_minutes", 15) or 15),
                    consent_timeout_seconds=float(get("consent_timeout_seconds", 15) or 15))


def identity(s: Settings) -> Identity:
    return load_or_create(data_dir(), HermesSecretStore(), f"tether-{s.name}")
