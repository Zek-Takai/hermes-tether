"""TLS 1.3 contexts with pinned certificates and the 256-bit gate (design §5.2, D5, D11).

- TLS 1.3 only. Both 256-bit suites are allowed; negotiation picks the best for the pair (D11).
- Python's stdlib cannot pre-restrict TLS 1.3 suites, so ``gate`` runs right after the handshake and before
  any application byte, and closes the link unless a 256-bit suite was negotiated.
- Trust is a pinned SHA-256 fingerprint. Pinned peer certificates are also loaded as the verify roots, so
  OpenSSL checks the peer's signature and validity, and ``gate`` re-checks the exact fingerprint.
"""
from __future__ import annotations

import _ssl
import ssl
from typing import Iterable, Optional

from .identity import Identity, fingerprint

ALLOWED_SUITES = frozenset({"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"})


class LinkSecurityError(Exception):
    """The connection must be closed: wrong peer, weak suite, or wrong protocol."""


def _stdlib_context_class() -> type:
    """The real ``ssl.SSLContext``. Hermes injects truststore at startup (agent/ssl_verify.py), which replaces
    ``ssl.SSLContext`` with a subclass that also verifies every peer against the OS trust store; macOS rejects
    our pinned Ed25519 certificates there ("broken key size"). Trust on this link is the pin, so the link
    uses the stdlib class and never consults the OS store (or any CA)."""
    for cls in ssl.SSLContext.__mro__:
        if cls.__module__ == "ssl" and cls.__name__ == "SSLContext":
            return cls
    return ssl.SSLContext


def _set(ctx: ssl.SSLContext, name: str, value) -> None:
    """Set a context field through the C type. The stdlib's Python properties reach it with
    ``super(SSLContext, SSLContext)`` via the module global, which truststore has replaced, so on a stdlib
    context they recurse forever once truststore is injected."""
    getattr(_ssl._SSLContext, name).__set__(ctx, value)


def _base(purpose: ssl.Purpose, ident: Identity) -> ssl.SSLContext:
    server = purpose == ssl.Purpose.CLIENT_AUTH
    ctx = _stdlib_context_class()(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    _set(ctx, "minimum_version", ssl.TLSVersion.TLSv1_3)
    _set(ctx, "maximum_version", ssl.TLSVersion.TLSv1_3)
    _set(ctx, "check_hostname", False)          # identity is the pin, not a hostname
    ctx.load_cert_chain(certfile=_tmp_cert(ident), keyfile=str(ident.key_path),
                        password=ident.password_callback())
    return ctx


_cert_files: dict[str, str] = {}


def _tmp_cert(ident: Identity) -> str:
    """``load_cert_chain`` wants a path; the certificate is public, so a private temp file is fine."""
    import os
    import tempfile
    path = _cert_files.get(ident.fp)
    if path and os.path.exists(path):
        return path
    fd, path = tempfile.mkstemp(prefix="tether-", suffix=".crt")
    with os.fdopen(fd, "wb") as fh:
        fh.write(ident.cert_pem)
    _cert_files[ident.fp] = path
    return path


def server_context(ident: Identity, pinned_peer_certs: Iterable[bytes], *, require_client_cert: bool) -> ssl.SSLContext:
    """Host side. Normal links require a pinned device certificate; the pairing listener does not (the
    device proves itself inside the link, see pairing.py)."""
    ctx = _base(ssl.Purpose.CLIENT_AUTH, ident)
    certs = b"".join(pinned_peer_certs)
    if require_client_cert:
        if not certs:
            raise LinkSecurityError("no paired devices: nothing to accept")
        ctx.load_verify_locations(cadata=certs.decode())
        _set(ctx, "verify_mode", ssl.CERT_REQUIRED)
    else:
        _set(ctx, "verify_mode", ssl.CERT_NONE)
    return ctx


def client_context(ident: Identity, pinned_host_cert: Optional[bytes]) -> ssl.SSLContext:
    """Device side. With a pinned host certificate OpenSSL verifies it; during pairing there is none yet
    and ``gate`` checks the fingerprint from the pairing link instead."""
    ctx = _base(ssl.Purpose.SERVER_AUTH, ident)
    if pinned_host_cert:
        ctx.load_verify_locations(cadata=pinned_host_cert.decode())
        _set(ctx, "verify_mode", ssl.CERT_REQUIRED)
    else:
        _set(ctx, "verify_mode", ssl.CERT_NONE)
    return ctx


def gate(ssl_obj: ssl.SSLObject | ssl.SSLSocket, *, expected_peer_fp: Optional[str] = None,
         allowed_peer_fps: Optional[set[str]] = None) -> dict:
    """Run before any application data. Raises LinkSecurityError, else returns what was negotiated."""
    version = ssl_obj.version()
    suite, _, bits = ssl_obj.cipher() or ("", "", 0)
    if version != "TLSv1.3":
        raise LinkSecurityError(f"refused: {version} (TLS 1.3 required)")
    if suite not in ALLOWED_SUITES:
        raise LinkSecurityError(f"refused: {suite} ({bits}-bit); a 256-bit suite is required")
    der = ssl_obj.getpeercert(binary_form=True)
    peer_fp = fingerprint(der) if der else None
    if expected_peer_fp is not None and peer_fp != expected_peer_fp:
        raise LinkSecurityError("refused: peer certificate does not match the pinned fingerprint")
    if allowed_peer_fps is not None and peer_fp not in allowed_peer_fps:
        raise LinkSecurityError("refused: peer certificate is not paired")
    return {"version": version, "suite": suite, "bits": bits, "peer_fp": peer_fp}
