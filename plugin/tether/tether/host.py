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
from .machine import clean_announce, clean_os, clean_version
from .store import DevicePins, log_event

logger = logging.getLogger(__name__)

PRIVATE_FACTS = frozenset({"hostname"})   # a device's own computer name is never shown or passed on

ConfirmFn = Callable[[str, dict[str, Any]], Awaitable[bool]]


class _PairingOver(pairing.PairingError):
    """A pairing error that ends the owner's `hermes tether pair` at once (the offer cannot be used any more)."""


def pair_sig_message(nonce: bytes, host_fp: str) -> bytes:
    return b"tether-pair-sig-v1\x00" + nonce + b"\x00" + host_fp.encode()


@dataclass
class DeviceConn:
    name: str
    peer: Peer
    announce: dict[str, Any] = field(default_factory=dict)
    link: dict[str, Any] = field(default_factory=dict)
    connected_at: float = field(default_factory=time.time)
    fp: str = ""                                    # the certificate this link was authenticated with


class HostService:
    WATCH_INTERVAL_S = 3.0

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
        """Start listening and watching the pins. A first load that fails (the listen address is not up yet at boot,
        the port is held, a pin the listener cannot be built from) is not an error here: nothing listens, and the
        watcher tries again every WATCH_INTERVAL_S, as after a failed reload (F37). The service always starts, so
        this process owns the link and other processes relay through it instead of waiting forever."""
        self._watch = asyncio.create_task(self._watch_pins())
        try:
            await self._reload()
        except Exception as e:  # noqa: BLE001
            logger.warning("tether host: could not start listening: %s; trying again", e)
            self._pins_mtime = -1.0

    async def _cut(self, name: str, reason: str) -> None:
        """End a registered link and record it, so the connection log and last_seen show the key was cut off."""
        conn = self.devices.pop(name, None)
        if conn is None:
            return
        self.last_seen[name] = time.time()
        log_event(self.pins.path.parent, "device_disconnected", device=name, reason=reason)
        await conn.peer.close()

    async def _reload(self) -> None:
        self._pins_mtime = self.pins.mtime()
        if self._server is not None:
            self._server.close()
            self._server = None
        pinned = self.pins.all()
        # unpaired, or a different key now pinned under the same name: the old key's link must not stay up
        for name in [n for n, c in self.devices.items() if n not in pinned or c.fp != pinned[n]["fp"]]:
            await self._cut(name, "unpaired" if name not in pinned else "key replaced")
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
            await asyncio.sleep(self.WATCH_INTERVAL_S)
            if self.pins.mtime() == self._pins_mtime:
                continue
            try:
                await self._reload()
            except Exception as e:  # noqa: BLE001
                # fail closed: pins that cannot be applied cut every live link; the next round tries again
                logger.warning("tether host: could not apply the paired devices: %s", e)
                self._pins_mtime = -1.0
                for name in list(self.devices):
                    await self._cut(name, "pins could not be applied")

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
        # the pins may have changed while the hello was held back (unpair, or another key under this name): check
        # again here, with no await between this check and the registration below
        if (self.pins.all().get(name) or {}).get("fp") != info["peer_fp"]:
            log_event(self.pins.path.parent, "connection_refused", reason="key no longer paired")
            writer.close()
            return
        old = self.devices.get(name)
        conn = DeviceConn(name, None, fp=info["peer_fp"],  # type: ignore[arg-type]
                          link={"suite": info["suite"], "bits": info["bits"]})

        def on_event(h: dict, body: bytes) -> None:
            if h.get("kind") == "announce":
                conn.announce = clean_announce(h.get("data"))    # only checked facts reach model, panel, CLI

        def on_close(peer: Peer) -> None:
            if self.devices.get(name) is conn:
                self.devices.pop(name, None)
                self.last_seen[name] = time.time()
                log_event(self.pins.path.parent, "device_disconnected", device=name)

        conn.peer = Peer(reader, writer, name=name, handlers={}, on_event=on_event, on_close=on_close)
        self.devices[name] = conn
        if old:                                  # registered first, so closing the old link cannot cut this one
            await old.peer.close()
        logger.info("tether host: %s connected (%s)", name, info["suite"])
        log_event(self.pins.path.parent, "device_connected", device=name, link=info["suite"])
        await conn.peer.serve()

    async def call(self, device: str, kind: str, args: dict[str, Any], body: bytes = b"",
                   timeout: float = 120.0, expect_fp: str = "") -> tuple[dict[str, Any], bytes]:
        """One call to the device linked under this name. ``expect_fp``: send only over a link authenticated as
        that key (D43), so a grant token never reaches a key it did not come from; nothing is sent otherwise."""
        conn = self.devices.get(device)
        if conn is None:
            since = self.last_seen.get(device)
            when = f" since {time.strftime('%H:%M', time.localtime(since))}" if since else ""
            if device not in self.pins.all():
                raise ConnectionError(f"no paired device named {device!r}")
            raise ConnectionError(f"{device} is offline{when} (asleep, or its Hermes is not running)")
        if (self.pins.all().get(device) or {}).get("fp") != conn.fp:
            # the pin changed and the watcher has not reloaded yet: this link is no longer the paired key
            await self._cut(device, "key no longer paired")
            raise ConnectionError(f"{device} is offline (its link does not match the paired key)")
        if expect_fp and conn.fp != expect_fp:
            raise ConnectionError(f"{device} is now a different paired key than this session was opened with, so "
                                  "this did not run anywhere")
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
            if conn is not None and conn.fp != rec.get("fp"):
                conn = None          # a link of a key no longer pinned under this name (the watcher cuts it soon)
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
        # one request at a time reaches the owner: a key line and its 'Pair it?' belong together, and after a yes
        # the offer is burned, so a request that waited is refused before the owner is asked again
        owner_turn = asyncio.Lock()

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
                async with owner_turn:
                    # checked here, under the lock: once another request was answered yes the offer is gone
                    host_proof = book.check(name, self.ident.fp, dev_fp, nonce, proof)
                    details = {"fp": dev_fp, "os": clean_os(hello.get("os")),
                               "hermes": clean_version(hello.get("hermes"))}
                    if not await confirm(name, details):                      # owner says yes on the host
                        await frames.write_frame(writer, {"t": "pair_denied"})
                        raise pairing.PairingError("the host owner declined this device")
                    # The answer goes to the device first and the key is pinned only once it was sent: a device that
                    # gave up while the owner was reading is not paired, and the owner is told so now (F68).
                    book.burn(name)
                    try:
                        await frames.write_frame(writer, {"t": "pair_ok",
                                                          "host_proof": base64.b64encode(host_proof).decode(),
                                                          "link_port": self.listen_port, "host_label": self.label})
                    except Exception:  # noqa: BLE001
                        raise _PairingOver("the device left before it got the answer; nothing was paired. Run "
                                           "`hermes tether pair` again") from None
                    # store the certificate as parsed, not the device's text (a second PEM block would break reloads)
                    self.pins.add(name, dev_fp, cert.public_bytes(serialization.Encoding.PEM).decode())
                if not done.done():
                    done.set_result({"name": name, **details})
            except Exception as e:  # noqa: BLE001
                logger.warning("tether pairing: %s", e)
                over = isinstance(e, _PairingOver) or (isinstance(e, pairing.PairingError) and "revoked" in str(e))
                if over and not done.done():
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
