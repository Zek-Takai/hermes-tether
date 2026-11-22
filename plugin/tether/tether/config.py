"""Settings, identity and the long-lived services, shared by the gateway process and the CLI."""
from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from typing import Any, Callable

from .identity import HermesSecretStore, Identity, load_or_create, protect_passphrase
from .store import DEFAULT_GRANT_IDLE_MINUTES, data_dir, default_unlocked, flag

DEFAULT_PORT = 9130          # link; pairing uses the next port, only while `hermes tether pair` runs


@dataclass
class Settings:
    roles: set
    name: str
    listen_host: str
    listen_port: int
    grant_idle_minutes: float
    consent_timeout_seconds: float
    allow_unlocked_commands: bool = False     # D73: commands run without the session lock (default: Windows on)

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
                    grant_idle_minutes=float(get("grant_idle_minutes", DEFAULT_GRANT_IDLE_MINUTES) or DEFAULT_GRANT_IDLE_MINUTES),
                    consent_timeout_seconds=float(get("consent_timeout_seconds", 60) or 60),
                    allow_unlocked_commands=flag(get("allow_unlocked_commands", None), default_unlocked()))


_IDENTITIES: dict[tuple[str, str], Identity] = {}
_IDENTITY_LOCK = threading.Lock()


def identity(s: Settings) -> Identity:
    """Loaded once per process. Later calls return the same object and never read the passphrase again,
    because by then it has been taken out of the environment (protect_passphrase)."""
    key = (str(data_dir()), f"tether-{s.name}")
    with _IDENTITY_LOCK:
        if key not in _IDENTITIES:
            store = HermesSecretStore()
            _IDENTITIES[key] = load_or_create(data_dir(), store, key[1])
            protect_passphrase(store)     # load_or_create may just have created and stored a passphrase
        return _IDENTITIES[key]


def reset_identity_cache() -> None:
    """Tests only: forget the loaded identities so the next call loads them again."""
    with _IDENTITY_LOCK:
        _IDENTITIES.clear()
