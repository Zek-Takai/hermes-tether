"""Long-term identity for one machine: an Ed25519 key and a self-signed certificate made from it.

Storage follows Hermes's normal secret path (design D13):
- the private key lives on disk only ENCRYPTED (PEM, BestAvailableEncryption) in the plugin's data folder;
- the passphrase that unlocks it is a Hermes secret (``TETHER_KEY_PASSPHRASE``), stored and read through
  Hermes's own env-secret functions, so it sits in ``.env`` or whatever secret source the user configured;
- the certificate and the pins are not secret.
Python's ``ssl`` can only load a key from a file, so the encrypted file plus passphrase means the plain key
never touches disk.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

PASSPHRASE_SECRET = "TETHER_KEY_PASSPHRASE"
LEGACY_PASSPHRASE_SECRETS = ("HOMEPORT_KEY_PASSPHRASE",)   # the working name before 2026-11-06
KEY_FILE = "identity.key.enc"
CERT_FILE = "identity.crt"


class SecretStore(Protocol):
    """Where the passphrase lives. Production: Hermes's env secrets. Tests: memory."""

    def get(self, name: str) -> Optional[str]: ...

    def put(self, name: str, value: str) -> None: ...


class HermesSecretStore:
    """Hermes's normal path: the same functions `hermes config set` uses for secrets."""

    def get(self, name: str) -> Optional[str]:
        """Hermes's public secret API first (catalog rule 11: honours the active profile's scope under
        multiplexing); with no scope bound yet (plugin start-up), Hermes's own config reader."""
        try:
            from agent.secret_scope import get_secret
            value = get_secret(name)
            if value:
                return value
        except Exception:  # noqa: BLE001 - UnscopedSecretError at start-up, or an older Hermes
            pass
        from hermes_cli.config import get_env_value
        return get_env_value(name) or None

    def put(self, name: str, value: str) -> None:
        from hermes_cli.config import save_env_value_secure
        save_env_value_secure(name, value)


class MemorySecretStore:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def get(self, name: str) -> Optional[str]:
        return self._values.get(name)

    def put(self, name: str, value: str) -> None:
        self._values[name] = value


def fingerprint(cert_der: bytes) -> str:
    """SHA-256 of the DER certificate, lowercase hex: what both sides pin."""
    return hashlib.sha256(cert_der).hexdigest()


@dataclass(frozen=True)
class Identity:
    cert_pem: bytes
    key_path: Path          # encrypted PEM on disk
    passphrase: bytes       # unlocks key_path; never logged, never returned to the agent

    @property
    def cert_der(self) -> bytes:
        return x509.load_pem_x509_certificate(self.cert_pem).public_bytes(serialization.Encoding.DER)

    @property
    def fp(self) -> str:
        return fingerprint(self.cert_der)

    def password_callback(self) -> Callable[[], bytes]:
        return lambda: self.passphrase


def _make_cert(key: Ed25519PrivateKey, common_name: str) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            # Trust is the pinned fingerprint, not the date; a long life avoids silent expiry breaks.
            .not_valid_after(now + _dt.timedelta(days=365 * 20))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, algorithm=None))
    return cert.public_bytes(serialization.Encoding.PEM)


def load_or_create(data_dir: Path, store: SecretStore, common_name: str) -> Identity:
    """Load this machine's identity, creating it on first use."""
    data_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(data_dir, 0o700)
    key_path, cert_path = data_dir / KEY_FILE, data_dir / CERT_FILE
    raw = store.get(PASSPHRASE_SECRET)
    if not raw:
        for legacy in LEGACY_PASSPHRASE_SECRETS:   # carried over through Hermes's own secret store, never logged
            raw = store.get(legacy)
            if raw:
                store.put(PASSPHRASE_SECRET, raw)
                break
    if key_path.exists() and cert_path.exists() and raw:
        passphrase = base64.urlsafe_b64decode(raw.encode())
        serialization.load_pem_private_key(key_path.read_bytes(), password=passphrase)  # fails loudly if wrong
        return Identity(cert_path.read_bytes(), key_path, passphrase)
    if key_path.exists() or cert_path.exists():
        raise RuntimeError(
            f"tether identity in {data_dir} is incomplete (key, certificate or the {PASSPHRASE_SECRET} "
            "secret is missing); remove the folder to create a new identity, then pair again")
    passphrase = secrets.token_bytes(32)
    key = Ed25519PrivateKey.generate()
    enc = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(passphrase))
    cert_pem = _make_cert(key, common_name)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(enc)
    cert_path.write_bytes(cert_pem)
    store.put(PASSPHRASE_SECRET, base64.urlsafe_b64encode(passphrase).decode())
    return Identity(cert_pem, key_path, passphrase)
