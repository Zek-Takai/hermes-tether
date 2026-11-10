"""Device side: dial out to the paired host, keep the link, run calls through this machine's Hermes after the
person here allowed the session (design §3, D10, D12, D15, D20)."""
from __future__ import annotations

import asyncio
import base64
import logging
import random
from typing import Any, Awaitable, Callable, Optional

from cryptography.hazmat.primitives import serialization

from . import frames, pairing, tlslink
from .consent import ConsentGate
from .identity import Identity
from .link import Peer
from .machine import local_facts
from .store import HostPin, log_event, read_panel_settings

logger = logging.getLogger(__name__)

Handler = Callable[[dict[str, Any], bytes], Awaitable[tuple[dict[str, Any], bytes]]]


_local_facts = local_facts   # what this machine says about itself (machine.py)


class DeviceService:
    def __init__(self, ident: Identity, host_pin: HostPin, consent: ConsentGate, name: str,
                 handlers: dict[str, Handler], capabilities: Callable[[], dict[str, Any]]) -> None:
        self.ident, self.host_pin, self.consent, self.name = ident, host_pin, consent, name
        self._handlers, self._capabilities = handlers, capabilities
        self.peer: Optional[Peer] = None
        self.host_label = "the paired host"
        self._task: Optional[asyncio.Task] = None
        self._connected_key: Optional[tuple] = None     # (host, port, fp) of the live connection
        self._redial = asyncio.Event()
        self.workspaces = None                  # D24: set by the plugin when the device role starts

    @property
    def paused(self) -> bool:
        """`hermes tether pause` on this device (a flag file, so the CLI reaches the running gateway)."""
        if (self.host_pin.path.parent / "paused").exists():
            self.consent.revoke_all()
            return True
        return False

    # ---------- the link ----------
    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())
            self._settings_task = asyncio.create_task(self._watch_settings())
            if self.workspaces is not None:
                self._sweeper = asyncio.create_task(self._sweep())

    SETTINGS_POLL_S = 5.0

    async def apply_panel_settings(self) -> bool:
        """The Tether panel's choices (settings.json) win over config.yaml; applied live, then re-announced
        so the host shows the new idle limit at once. True when something changed."""
        s = read_panel_settings(self.host_pin.path.parent)
        changed = False
        idle = s.get("grant_idle_minutes")
        if idle is not None and abs(self.consent.idle_s / 60 - idle) > 1e-6:
            self.consent.set_idle_minutes(idle)
            changed = True
        timeout = s.get("consent_timeout_seconds")
        if timeout is not None and abs(self.consent.timeout_s - timeout) > 1e-6:
            self.consent.timeout_s = timeout
            changed = True
        if changed:
            log_event(self.host_pin.path.parent, "settings_changed",
                      reason=f"idle {self.consent.idle_s / 60:g} min, consent wait {self.consent.timeout_s:g} s")
            if self.peer is not None:
                try:
                    await self.peer.event("announce", {"name": self.name, **_local_facts(), **self._capabilities()})
                except Exception:  # noqa: BLE001 - the next connect announces again
                    pass
        return changed

    @staticmethod
    def _pin_key(rec: Optional[dict[str, Any]]) -> Optional[tuple]:
        return (rec.get("host"), rec.get("port"), rec.get("fp")) if rec else None

    async def follow_host_pin(self) -> bool:
        """Re-paired to another host (or unpaired) while connected: end every session grant, drop the old link
        and let the connection loop dial the new host now, without a gateway restart. True when it switched."""
        if self.peer is None or self.peer.closed.is_set() or self._connected_key is None:
            return False
        if self._pin_key(self.host_pin.get()) == self._connected_key:
            return False
        logger.info("tether device: host pairing changed; leaving %s", self.host_label)
        log_event(self.host_pin.path.parent, "host_changed", host=self.host_label)
        self.consent.revoke_all()                      # sessions granted to the old host end here
        self._connected_key = None
        self._redial.set()
        await self.peer.close()
        return True

    async def _watch_settings(self) -> None:
        while True:
            try:
                await self.apply_panel_settings()
                await self.follow_host_pin()
            except Exception:  # noqa: BLE001
                logger.warning("tether: applying panel settings failed", exc_info=True)
            await asyncio.sleep(self.SETTINGS_POLL_S)

    async def _sweep(self) -> None:
        """Remove workspaces whose session lost its grant (idle timer, pause) within a minute."""
        while True:
            await asyncio.sleep(60)
            try:
                live = self.consent.live_sessions()
                await asyncio.to_thread(self.workspaces.sweep, live)
            except Exception:  # noqa: BLE001
                logger.warning("tether: workspace sweep failed", exc_info=True)

    async def _run(self) -> None:
        delay = 1.0
        while True:
            rec = self.host_pin.get()
            if not rec:
                await asyncio.sleep(10)
                continue
            try:
                await self._connect_once(rec)
                delay = 1.0
            except Exception as e:  # noqa: BLE001 - network blips, host restarts: retry with backoff
                logger.info("tether device: link to %s:%s failed: %s", rec.get("host"), rec.get("port"), e)
            if self._redial.is_set():                  # a new pairing: dial it now, no backoff
                self._redial.clear()
                delay = 1.0
                continue
            await asyncio.sleep(delay + random.random())
            delay = min(delay * 2, 30.0)

    async def _connect_once(self, rec: dict[str, Any]) -> None:
        ctx = tlslink.client_context(self.ident, rec["cert_pem"].encode())
        reader, writer = await asyncio.wait_for(asyncio.open_connection(rec["host"], rec["port"], ssl=ctx), 15)
        tlslink.gate(writer.get_extra_info("ssl_object"), expected_peer_fp=rec["fp"])
        await frames.write_frame(writer, {"t": "hello", "protocol": frames.PROTOCOL, "role": "device",
                                          "name": self.name, **_local_facts()})
        hello, _ = await asyncio.wait_for(frames.read_frame(reader), 15)
        frames.check_hello(hello)
        self.host_label = hello.get("label") or self.host_label
        handlers = {kind: self._guard(kind, h) for kind, h in self._handlers.items()}
        self.peer = Peer(reader, writer, name="host", handlers=handlers)
        self._connected_key = self._pin_key(rec)
        logger.info("tether device: connected to %s", self.host_label)
        d = self.host_pin.path.parent
        log_event(d, "host_connected", host=self.host_label)
        serve = asyncio.create_task(self.peer.serve())
        try:
            await self.peer.event("announce", {"name": self.name, **_local_facts(), **self._capabilities()})
            await serve   # a reconnect keeps grants still inside their idle window (D15)
        finally:
            log_event(d, "host_disconnected", host=self.host_label)

    UNGUARDED = frozenset({"close_session"})     # closing never asks the person at the machine to allow it

    def _guard(self, kind: str, handler: Handler) -> Handler:
        if kind in self.UNGUARDED:
            return handler

        async def run(args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
            if self.paused:
                raise PermissionError("remote use is paused on this device")
            rec = self.host_pin.get() or {}
            await self.consent.require(rec.get("fp", ""), self.host_label, str(args.get("session") or "default"),
                                       str(args.get("session_title") or ""))
            return await handler(args, body)
        return run

    # ---------- joining (design §5.3) ----------
    async def join(self, link_text: str) -> dict[str, Any]:
        link = pairing.PairingLink.parse(link_text)
        ctx = tlslink.client_context(self.ident, None)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(link.host, link.port, ssl=ctx), 20)
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            tlslink.gate(ssl_obj, expected_peer_fp=link.host_fp)        # fake host fails here
            host_cert_pem = ssl_obj.getpeercert(binary_form=True)
            await frames.write_frame(writer, {"t": "hello", "protocol": frames.PROTOCOL, "role": "pair",
                                              "name": self.name, "cert_pem": self.ident.cert_pem.decode(),
                                              **_local_facts()})
            msg, _ = await asyncio.wait_for(frames.read_frame(reader), 20)
            if msg.get("t") != "pair_nonce":
                raise pairing.PairingError("host did not start pairing")
            nonce = base64.b64decode(msg["nonce"])
            proof = pairing.device_proof(link.secret, link.host_fp, self.ident.fp, self.name, nonce)
            key = serialization.load_pem_private_key(self.ident.key_path.read_bytes(), password=self.ident.passphrase)
            from .host import pair_sig_message
            sig = key.sign(pair_sig_message(nonce, link.host_fp))
            await frames.write_frame(writer, {"t": "pair_proof", "proof": base64.b64encode(proof).decode(),
                                              "sig": base64.b64encode(sig).decode()})
            try:
                ans, _ = await asyncio.wait_for(frames.read_frame(reader), pairing.DEFAULT_TTL_S)
            except (asyncio.IncompleteReadError, ConnectionError):
                raise pairing.PairingError("the host refused this pairing (wrong, used or expired link)") from None
            if ans.get("t") == "pair_denied":
                raise pairing.PairingError("the host owner declined this device")
            if ans.get("t") != "pair_ok":
                raise pairing.PairingError("pairing failed on the host")
            expect = pairing.host_proof(link.secret, link.host_fp, self.ident.fp, self.name, nonce)
            if not pairing.verify(expect, base64.b64decode(ans["host_proof"])):
                raise pairing.PairingError("the host could not prove it knows the pairing secret")
            from cryptography import x509
            pem = x509.load_der_x509_certificate(host_cert_pem).public_bytes(serialization.Encoding.PEM).decode()
            self.host_pin.set(host=link.host, port=int(ans["link_port"]), fp=link.host_fp, cert_pem=pem,
                              name=self.name, host_label=ans.get("host_label", ""))
            return {"host": link.host, "port": ans["link_port"], "host_label": ans.get("host_label", "")}
        finally:
            writer.close()
