"""Device side: dial out to the paired host, keep the link, run calls through this machine's Hermes after the
person here approved the session with a code from their authenticator app (design §3, D10, D12, D15, D20, D63)."""
from __future__ import annotations

import asyncio
import base64
import logging
import random
import re
import time
from typing import Any, Awaitable, Callable, Optional

from cryptography.hazmat.primitives import serialization

from . import frames, lock, pairing, tlslink
from .consent import ConsentGate
from .identity import Identity
from .link import Peer, call_expires
from .machine import local_facts
from .store import HostPin, log_event, read_panel_settings
from .workspace import check_session

logger = logging.getLogger(__name__)

Handler = Callable[[dict[str, Any], bytes], Awaitable[tuple[dict[str, Any], bytes]]]

PAUSED_TEXT = "remote use is paused on this device"
DEFAULT_HOST_LABEL = "the paired host"
# The host's label (as recorded at pairing) opens the approval box, so it is shown only as one short line of plain
# characters ("Hermes on studio-mac"); anything else is replaced by DEFAULT_HOST_LABEL (the reverse direction of D37).
_HOST_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._'-]{0,47}")


def checked_host_label(value: Any) -> str:
    """The label the host sent in its hello, if it has the shape of a short name; DEFAULT_HOST_LABEL otherwise."""
    if isinstance(value, str) and _HOST_LABEL_RE.fullmatch(value) and "  " not in value:
        return value
    return DEFAULT_HOST_LABEL


def box_host(rec: Optional[dict[str, Any]]) -> tuple[str, Optional[float]]:
    """The host as the approval box names it: its label as recorded on this device at pairing (checked by shape) and
    when it was paired. What the host says in its hello later never reaches the box (D64)."""
    rec = rec or {}
    paired = rec.get("paired_at")
    if not isinstance(paired, (int, float)) or isinstance(paired, bool):
        paired = None
    return checked_host_label(rec.get("host_label")), paired


_local_facts = local_facts   # what this machine says about itself (machine.py)


class DeviceService:
    def __init__(self, ident: Identity, host_pin: HostPin, consent: ConsentGate, name: str,
                 handlers: dict[str, Handler], capabilities: Callable[[], dict[str, Any]]) -> None:
        self.ident, self.host_pin, self.consent, self.name = ident, host_pin, consent, name
        self._handlers, self._capabilities = handlers, capabilities
        self.peer: Optional[Peer] = None
        self.host_label = DEFAULT_HOST_LABEL
        self._task: Optional[asyncio.Task] = None
        self._connected_key: Optional[tuple] = None     # (host, port, fp) of the live connection
        self._redial = asyncio.Event()
        self.workspaces = None                  # D24: set by the plugin when the device role starts
        # The sweeper's hooks, set by the plugin: ending sessions whose grant ended (LocalExec.sweep_jobs, which
        # also reaps background-job files) and the sessions with a call in flight (LocalExec.busy_sessions).
        self.job_sweep: Optional[Callable[[set[str]], int]] = None
        self.busy_sessions: Optional[Callable[[], set[str]]] = None
        self.seeds = None                       # D66: this device's authenticator (seedstore.SeedStore), set by the plugin
        self._was_paused = self._pause_flag()   # what follow_pause saw last; a device started paused has nothing to stop

    def _pause_flag(self) -> bool:
        """`hermes tether pause`, or an authenticator setup running on this machine (D67): while either holds, every
        grant ends, the link drops and every call is refused (D48), so nothing remote reaches the screen or the
        terminal while a setup box shows a key or recovery codes."""
        d = self.host_pin.path.parent
        if (d / "paused").exists():
            return True
        from .enroll import busy
        return busy(d)

    @property
    def paused(self) -> bool:
        """`hermes tether pause` on this device (a flag file, so the CLI reaches the running gateway)."""
        if self._pause_flag():
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
    PAUSE_POLL_S = 1.0          # Pause reaches work in flight within this long

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
        unlock = s.get("allow_unlocked_commands")
        if unlock is not None and unlock != lock.unlocked():
            # D73: the session lock is a "finger trap": what holds a session cannot be loosened by it. A change waits
            # until no remote session is connected or has a call in flight here (a session that reached the panel's
            # settings through another program gains nothing for itself), and is logged.
            busy = self.busy_sessions() if callable(self.busy_sessions) else set()
            if not self.consent.live_sessions() and not busy:
                lock.set_unlocked(unlock)
                changed = True
                logger.warning("tether: allow_unlocked_commands is now %s: remote commands %s", "on" if unlock else
                               "off", "run without the session lock" if unlock else "run inside the session lock "
                               "(macOS) or not at all (Windows)")
        if changed:
            log_event(self.host_pin.path.parent, "settings_changed",
                      reason=f"idle {self.consent.idle_s / 60:g} min, consent wait {self.consent.timeout_s:g} s, "
                             f"unlocked commands {'on' if lock.unlocked() else 'off'}")
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
        await self._end_sessions_now()                 # nothing of the old host's sessions waits for the new one
        return True

    async def follow_pause(self) -> bool:
        """Pause is the kill switch (DESIGN 5.1(5)). Reading `paused` ends every grant; on the change to paused the
        link is dropped as well, so everything in flight stops the way it does for a lost connection (Peer.close
        cancels each call's task): a running command is stopped, one still waiting for its terminal never starts, a
        screen action still waiting for the driver never reaches it, and an open Allow prompt is closed. While the
        device stays paused its link comes back and every call is refused with the reason. True when it dropped
        the link."""
        paused = self.paused
        was, self._was_paused = self._was_paused, paused
        if not paused or was or self.peer is None or self.peer.closed.is_set():
            return False
        logger.info("tether device: paused; stopping all remote work from %s", self.host_label)
        await self.peer.close()
        await self._end_sessions_now()
        return True

    UNWIND_S = 0.2              # time for the calls Peer.close cancelled to leave their sessions' stop handles

    async def _end_sessions_now(self) -> None:
        """After Pause or a re-pair has ended every grant and dropped the link: end the sessions here at once (their
        terminals, workspaces, stop handles) instead of at the next sweep, so a new Allow for the same session id
        never meets what an old one left. A call still unwinding keeps its session until the regular sweep."""
        await asyncio.sleep(self.UNWIND_S)
        try:
            await self.sweep_once()
        except Exception:  # noqa: BLE001 - the regular sweep tries again within a minute
            logger.warning("tether: ending sessions after pause or re-pair failed", exc_info=True)

    async def _watch_settings(self) -> None:
        settings_due = 0.0
        while True:
            try:
                await self.follow_pause()
            except Exception:  # noqa: BLE001
                logger.warning("tether: following pause failed", exc_info=True)
            if time.monotonic() >= settings_due:
                settings_due = time.monotonic() + self.SETTINGS_POLL_S
                try:
                    await self.apply_panel_settings()
                    await self.follow_host_pin()
                except Exception:  # noqa: BLE001
                    logger.warning("tether: applying panel settings failed", exc_info=True)
                if self.seeds is not None:
                    self.seeds.refresh()     # a change of the authenticator elsewhere, or `load`: read it again
            await asyncio.sleep(self.PAUSE_POLL_S)

    async def _sweep(self) -> None:
        """Within a minute, end every session whose grant ended here without a close (idle timer, Pause, a re-pair)."""
        while True:
            await asyncio.sleep(60)
            try:
                await self.sweep_once()
            except Exception:  # noqa: BLE001 - the next pass tries again
                logger.warning("tether: session sweep failed", exc_info=True)

    async def sweep_once(self) -> None:
        """One pass: a session with no live grant and no call in flight loses its workspace, its terminal, its stop
        handles, Hermes's file-tool state and its ended jobs' files, as close_session would remove them. A session
        with a call still in flight keeps everything until a later pass. The workspace sweep and the session/job
        sweep each have their own try: a failure of one never skips the other (F20)."""
        keep = self.consent.live_sessions()
        if self.busy_sessions is not None:
            keep |= self.busy_sessions()
        if self.workspaces is not None:
            try:
                await asyncio.to_thread(self.workspaces.sweep, keep)
            except Exception:  # noqa: BLE001 - the sessions and job files below are ended all the same
                logger.warning("tether: workspace sweep failed", exc_info=True)
        if self.job_sweep is not None:
            try:
                await asyncio.to_thread(self.job_sweep, keep)
            except Exception:  # noqa: BLE001
                logger.warning("tether: background-job sweep failed", exc_info=True)

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
        self.host_label = checked_host_label(hello.get("label"))     # logs and status only: the box uses the pin
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
        async def unguarded(args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
            return await handler({**args, "session": check_session(args.get("session"))}, body)

        if kind in self.UNGUARDED:
            return unguarded

        async def run(args: dict[str, Any], body: bytes) -> tuple[dict[str, Any], bytes]:
            if self.paused:
                raise PermissionError(PAUSED_TEXT)
            session = check_session(args.get("session"))      # no '.', '..', paths or control characters
            rec = self.host_pin.get() or {}
            fp = rec.get("fp", "")
            label, paired_at = box_host(rec)
            token, passive = str(args.get("grant") or ""), bool(args.get("passive"))
            # D33: the approval belongs to the caller holding its grant token; anyone else gets the code box again.
            # The box never outlasts the host's wait for this call (its deadline): a code is never asked for when
            # nobody will read the answer. The box names the host as recorded here at pairing (D64).
            granted = await self.consent.require(fp, label, session, token=token, passive=passive,
                                                 expires=call_expires(), paired_at=paired_at)
            if self.paused:              # paused while the prompt was up: reading `paused` revoked that Allow too
                raise PermissionError(PAUSED_TEXT)
            if passive:                                       # a poll: never counted as use (D38)
                data, out = await handler({**args, "session": session}, body)
            else:
                self.consent.call_started(fp, session)        # D44: a running call is not idle
                try:
                    data, out = await handler({**args, "session": session}, body)
                except BaseException:
                    if granted and not token:
                        # This call's own Allow, and its token can never reach the caller now (the call failed or
                        # was stopped): nobody holds it, so it ends here and the next call is asked for afresh (D45).
                        self.consent.release(fp, session, granted)
                    raise
                finally:
                    self.consent.call_ended(fp, session, granted or token)   # idle counts from the end of the call
            if self.paused:              # paused while it ran (before follow_pause dropped the link): nothing goes back
                raise PermissionError(PAUSED_TEXT)
            if granted:                                       # this call got the Allow: hand its token back
                data = {**(data or {}), "grant": granted}
            return data, out
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
            # The label recorded here is the one the approval box names (D51 shape check, D64): never raw host text.
            label = checked_host_label(ans.get("host_label"))
            self.host_pin.set(host=link.host, port=int(ans["link_port"]), fp=link.host_fp, cert_pem=pem,
                              name=self.name, host_label=label)
            return {"host": link.host, "port": ans["link_port"],
                    "host_label": "" if label == DEFAULT_HOST_LABEL else label}
        finally:
            writer.close()
