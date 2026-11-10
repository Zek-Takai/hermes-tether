"""Pairing: the master link (design §5.3, D5).

The host makes a one-time link ``tether://<host>:<port>/#<host_fp>.<secret>``: its certificate
fingerprint plus a 128-bit secret, single use, 10-minute expiry, bound to a device name. The device checks
the host certificate against ``host_fp`` before anything else, the 256-bit gate runs, the host sends a
nonce, and each side proves it knows the secret without sending it:

    device proof = HMAC-SHA256(secret, "device" | host_fp | device_fp | name | nonce)
    host proof   = HMAC-SHA256(secret, "host"   | host_fp | device_fp | name | nonce)

A man-in-the-middle sees different fingerprints on each side, so neither proof verifies; the nonce stops
replay. The host owner then confirms the device before it is pinned.
"""
from __future__ import annotations

import base64
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Optional
from urllib.parse import urlsplit

SCHEME = "tether"
SECRET_BYTES = 16                  # 128 bits: no PAKE needed (PAKE protects low-entropy codes)
NONCE_BYTES = 16
DEFAULT_TTL_S = 600
MAX_FAILURES = 3


class PairingError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass(frozen=True)
class PairingLink:
    host: str
    port: int
    host_fp: str
    secret: bytes

    def to_text(self) -> str:
        return f"{SCHEME}://{self.host}:{self.port}/#{self.host_fp}.{_b64(self.secret)}"

    @classmethod
    def parse(cls, text: str) -> "PairingLink":
        text = text.strip()
        parts = urlsplit(text)
        if parts.scheme != SCHEME or not parts.hostname or not parts.port or "." not in parts.fragment:
            raise PairingError("not a tether pairing link")
        fp, _, sec = parts.fragment.partition(".")
        secret = _unb64(sec)
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp) or len(secret) != SECRET_BYTES:
            raise PairingError("damaged pairing link (fingerprint or secret has the wrong shape)")
        return cls(parts.hostname, parts.port, fp, secret)


def _mac(secret: bytes, role: str, host_fp: str, device_fp: str, name: str, nonce: bytes) -> bytes:
    msg = b"\x00".join([b"tether-pair-v1", role.encode(), host_fp.encode(), device_fp.encode(),
                        name.encode(), nonce])
    return hmac.new(secret, msg, sha256).digest()


def device_proof(secret: bytes, host_fp: str, device_fp: str, name: str, nonce: bytes) -> bytes:
    return _mac(secret, "device", host_fp, device_fp, name, nonce)


def host_proof(secret: bytes, host_fp: str, device_fp: str, name: str, nonce: bytes) -> bytes:
    return _mac(secret, "host", host_fp, device_fp, name, nonce)


def verify(expected: bytes, got: bytes) -> bool:
    return hmac.compare_digest(expected, got)


@dataclass
class _Offer:
    secret: bytes
    expires: float
    nonces: set[bytes] = field(default_factory=set)
    failures: int = 0


class OfferBook:
    """Host side: open pairing offers. Single use, expiring, atomic burn (thread-safe)."""

    def __init__(self, clock=time.monotonic) -> None:
        self._offers: dict[str, _Offer] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def create(self, name: str, host: str, port: int, host_fp: str, ttl_s: float = DEFAULT_TTL_S) -> PairingLink:
        if not name or not name.replace("-", "").replace("_", "").isalnum():
            raise PairingError("device name: letters, digits, - and _ only")
        secret = secrets.token_bytes(SECRET_BYTES)
        with self._lock:
            self._offers[name] = _Offer(secret, self._clock() + ttl_s)   # a new offer replaces an old one
        return PairingLink(host, port, host_fp, secret)

    def new_nonce(self, name: str) -> bytes:
        with self._lock:
            offer = self._live(name)
            nonce = secrets.token_bytes(NONCE_BYTES)
            offer.nonces.add(nonce)
            return nonce

    def check(self, name: str, host_fp: str, device_fp: str, nonce: bytes, proof: bytes) -> bytes:
        """Verify the device's proof; returns the host proof. Does NOT burn (owner confirmation comes next)."""
        with self._lock:
            offer = self._live(name)
            if nonce not in offer.nonces:
                raise PairingError("unknown or reused nonce")
            offer.nonces.discard(nonce)                        # each nonce answers once
            if not verify(device_proof(offer.secret, host_fp, device_fp, name, nonce), proof):
                offer.failures += 1
                if offer.failures >= MAX_FAILURES:
                    self._offers.pop(name, None)               # too many wrong proofs: the link is dead
                    raise PairingError("pairing proof failed; offer revoked after repeated failures")
                raise PairingError("pairing proof failed")
            return host_proof(offer.secret, host_fp, device_fp, name, nonce)

    def burn(self, name: str) -> None:
        with self._lock:
            self._offers.pop(name, None)

    def _live(self, name: str) -> _Offer:
        offer = self._offers.get(name)
        if offer is None:
            raise PairingError(f"no open pairing offer for {name!r}")
        if self._clock() > offer.expires:
            self._offers.pop(name, None)
            raise PairingError(f"pairing offer for {name!r} expired")
        return offer
