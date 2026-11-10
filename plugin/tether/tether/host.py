"""Host side: accept paired devices, keep a registry, forward calls; run pairing offers (design §3, §5.3)."""
from __future__ import annotations

import asyncio
import base64
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import frames, pairing, tlslink
from .identity import Identity, fingerprint
from .link import Peer
from .store import DevicePins, log_event

logger = logging.getLogger(__name__)

PRIVATE_FACTS = frozenset({"hostname"})   # a device's own computer name is never shown or passed on

ConfirmFn = Callable[[str, dict[str, Any]], Awaitable[bool]]


def pair_sig_message(nonce: bytes, host_fp: str) -> bytes:
    return b"tether-pair-sig-v1\x00" + nonce + b"\x00" + host_fp.encode()


@dataclass
class DeviceConn:
    name: str
    peer: Peer
    announce: dict[str, Any] = field(default_factory=dict)
    link: dict[str, Any] = field(default_factory=dict)
    connected_at: float = field(default_factory=time.time)


class HostService:
    def __init__(self, ident: Identity, pins: DevicePins, listen_host: str, listen_port: int,
                 label: str = "") -> None:
        self.ident, self.pins = ident, pins
        self.listen_host, self.listen_port = listen_host, listen_port
        self.label = label or f"Hermes on {socket.gethostname().split('.')[0]}"
        self.devices: dict[str, DeviceConn] = {}
        self.last_seen: dict[str, float] = {}
        self._server: Optional[asyncio.base_events.Server] = None
        self._pins_mtime = -1.0
        self._watch: Optional[asyncio.Task] = None

    # ---------- normal links ----------
    async def start(self) -> None:
        await self._reload()
        self._watch = asyncio.create_task(self._watch_pins())

    async def _reload(self) -> None:
        self._pins_mtime = self.pins.mtime()
        if self._server is not None:
            self._server.close()
            self._server = None
        pinned = self.pins.all()
        for name in [n for n in self.devices if n not in pinned]:      # unpaired: cut it off now
            await self.devices.pop(name).peer.close()
        certs = [v["cert_pem"].encode() for v in pinned.values()]
        if not certs:
            logger.info("tether host: no paired devices yet; not listening")
            return
        ctx = tlslink.server_context(self.ident, certs, require_client_cert=True)
        self._server = await asyncio.start_server(self._accept, self.listen_host, self.listen_port, ssl=ctx)
        logger.info("tether host: listening on %s:%s for %d device(s)", self.listen_host, self.listen_port,
                    len(certs))

    async def _watch_pins(self) -> None:
        while True:
            await asyncio.sleep(3)
            if self.pins.mtime() != self._pins_mtime:
                await self._reload()

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        by_fp = self.pins.by_fp()
        try:
            info = tlslink.gate(writer.get_extra_info("ssl_object"), allowed_peer_fps=set(by_fp))
        except tlslink.LinkSecurityError as e:
            logger.warning("tether host: refused a connection: %s", e)
            log_event(self.pins.path.parent, "connection_refused", reason="not a paired device")
            writer.close()
            return
        name = by_fp[info["peer_fp"]]
        try:
            hello, _ = await asyncio.wait_for(frames.read_frame(reader), 15)
            frames.check_hello(hello)
            await frames.write_frame(writer, {"t": "hello", "protocol": frames.PROTOCOL, "role": "host",
                                              "label": self.label})
        except Exception as e:  # noqa: BLE001
            logger.warning("tether host: %s failed hello: %s", name, e)
            writer.close()
            return
        old = self.devices.get(name)
        if old:
            await old.peer.close()
        conn = DeviceConn(name, None, link={"suite": info["suite"], "bits": info["bits"]})  # type: ignore[arg-type]

        def on_event(h: dict, body: bytes) -> None:
            if h.get("kind") == "announce":
                conn.announce = h.get("data") or {}

        def on_close(peer: Peer) -> None:
            if self.devices.get(name) is conn:
                self.devices.pop(name, None)
                self.last_seen[name] = time.time()
                log_event(self.pins.path.parent, "device_disconnected", device=name)

        conn.peer = Peer(reader, writer, name=name, handlers={}, on_event=on_event, on_close=on_close)
        self.devices[name] = conn
        logger.info("tether host: %s connected (%s)", name, info["suite"])
        log_event(self.pins.path.parent, "device_connected", device=name, link=info["suite"])
        await conn.peer.serve()

    async def call(self, device: str, kind: str, args: dict[str, Any], body: bytes = b"",
                   timeout: float = 120.0) -> tuple[dict[str, Any], bytes]:
        conn = self.devices.get(device)
        if conn is None:
            since = self.last_seen.get(device)
            when = f" since {time.strftime('%H:%M', time.localtime(since))}" if since else ""
            if device not in self.pins.all():
                raise ConnectionError(f"no paired device named {device!r}")
            raise ConnectionError(f"{device} is offline{when} (asleep, or its Hermes is not running)")
        return await conn.peer.call(kind, args, body, timeout)

    async def list_devices(self, may_own: bool = True) -> list[dict[str, Any]]:
        return self.status()

    async def close(self) -> None:
        if self._watch:
            self._watch.cancel()
            self._watch = None
        if self._server is not None:
            self._server.close()
            self._server = None
        for conn in list(self.devices.values()):
            await conn.peer.close()
        self.devices.clear()

    def status(self) -> list[dict[str, Any]]:
        rows = []
        for name, rec in sorted(self.pins.all().items()):
            conn = self.devices.get(name)
            caps = {k: v for k, v in (conn.announce if conn else {}).items() if k not in PRIVATE_FACTS}
            rows.append({"name": name, "online": conn is not None, "fp": rec["fp"][:16],
                         "link": conn.link if conn else {}, "capabilities": caps,
                         "last_seen": self.last_seen.get(name), "host_idle_minutes": rec.get("idle_minutes")})
        return rows

    # ---------- pairing (design §5.3) ----------
    async def pair(self, name: str, advertise_host: str, pairing_port: int, confirm: ConfirmFn,
                   on_link: Callable[[str], None], ttl_s: float = pairing.DEFAULT_TTL_S) -> dict[str, Any]:
        """Open a one-time pairing listener, hand the link to ``on_link``, wait for one device."""
        book = pairing.OfferBook()
        link = book.create(name, advertise_host, pairing_port, self.ident.fp, ttl_s)
        done: asyncio.Future = asyncio.get_running_loop().create_future()

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                tlslink.gate(writer.get_extra_info("ssl_object"))           # 256-bit before anything
                hello, _ = await asyncio.wait_for(frames.read_frame(reader), 20)
                frames.check_hello(hello)
                if hello.get("role") != "pair" or hello.get("name") != name:
                    raise pairing.PairingError("unexpected pairing request")
                cert_pem = hello["cert_pem"].encode()
                cert = x509.load_pem_x509_certificate(cert_pem)
                from cryptography.hazmat.primitives import serialization
                dev_fp = fingerprint(cert.public_bytes(serialization.Encoding.DER))
                nonce = book.new_nonce(name)
                await frames.write_frame(writer, {"t": "pair_nonce", "nonce": base64.b64encode(nonce).decode()})
                msg, _ = await asyncio.wait_for(frames.read_frame(reader), 20)
                proof = base64.b64decode(msg["proof"])
                sig = base64.b64decode(msg["sig"])
                pub = cert.public_key()
                if not isinstance(pub, Ed25519PublicKey):
                    raise pairing.PairingError("device key must be Ed25519")
                pub.verify(sig, pair_sig_message(nonce, self.ident.fp))      # device owns that cert's key
                host_proof = book.check(name, self.ident.fp, dev_fp, nonce, proof)
                details = {"fp": dev_fp, "os": hello.get("os", "?"), "hermes": hello.get("hermes", "?")}
                if not await confirm(name, details):                          # owner says yes on the host
                    await frames.write_frame(writer, {"t": "pair_denied"})
                    raise pairing.PairingError("the host owner declined this device")
                self.pins.add(name, dev_fp, cert_pem.decode())
                book.burn(name)
                await frames.write_frame(writer, {"t": "pair_ok", "host_proof": base64.b64encode(host_proof).decode(),
                                                  "link_port": self.listen_port, "host_label": self.label})
                if not done.done():
                    done.set_result({"name": name, **details})
            except Exception as e:  # noqa: BLE001
                logger.warning("tether pairing: %s", e)
                if isinstance(e, pairing.PairingError) and "revoked" in str(e) and not done.done():
                    done.set_exception(e)
            finally:
                writer.close()

        ctx = tlslink.server_context(self.ident, [], require_client_cert=False)
        server = await asyncio.start_server(handle, self.listen_host, pairing_port, ssl=ctx)
        try:
            on_link(link.to_text())
            return await asyncio.wait_for(done, ttl_s)
        except asyncio.TimeoutError:
            raise pairing.PairingError("pairing link expired with no device") from None
        finally:
            server.close()
            book.burn(name)
