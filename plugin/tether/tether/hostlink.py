"""Every Hermes process on the host gets the link (design §3, Host role; found live 2026-11-06).

Hermes runs agent turns in more than one process: Desktop sessions in the dashboard backend (``hermes
dashboard``; the SSH Desktop route starts its own ``serve`` child), messaging in ``gateway run``, plus CLI
chats. Only one process can hold the device listener, so the first to take ``link.lock`` owns the link
(``HostService``) and serves a private local relay on ``link.sock`` (owner-only file in the 0700 data folder);
every other process relays its calls through it. When the owner exits its lock is released and the next
process that needs the link takes over.
"""
from __future__ import annotations

import asyncio
import atexit
import contextlib
import fcntl
import logging
import os
from pathlib import Path
from typing import Any, Callable, Optional

from .link import Peer
from .store import DevicePins

logger = logging.getLogger(__name__)

LOCK_FILE = "link.lock"
SOCK_FILE = "link.sock"
RELAY_SLACK_S = 10.0


class HostLink:
    def __init__(self, d: Path, make_service: Callable[[], Any]) -> None:
        self.dir = d
        self.pins = DevicePins(d)
        self._make_service = make_service
        self.service = None                 # HostService while this process owns the link
        self._lock_fh = None
        self._relay_server: Optional[asyncio.base_events.Server] = None
        self._peer: Optional[Peer] = None
        self._clients: set[Peer] = set()        # owner: relay connections from other processes
        self._ensure_lock = asyncio.Lock()
        self._exit_hook = False

    @property
    def role(self) -> str:
        return "owner" if self.service else ("relay" if self._peer and not self._peer.closed.is_set() else "idle")

    # ---------- ownership ----------
    def _try_lock(self) -> bool:
        fh = open(self.dir / LOCK_FILE, "a+")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            return False
        self._lock_fh = fh
        return True

    async def ensure(self, may_own: bool = True) -> None:
        async with self._ensure_lock:
            if self.service is not None or (self._peer and not self._peer.closed.is_set()):
                return
            if may_own and self._try_lock():
                await self._become_owner()
                return
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(str(self.dir / SOCK_FILE)), 5)
            except (OSError, asyncio.TimeoutError):
                if may_own and self._try_lock():           # the owner just went away
                    await self._become_owner()
                    return
                raise ConnectionError("the tether link on this host is starting or restarting; try again "
                                      "in a few seconds") from None
            self._peer = Peer(reader, writer, name="tether owner", handlers={})
            asyncio.create_task(self._peer.serve())
            logger.info("tether host: relaying through this host's link owner (pid in %s)", LOCK_FILE)

    async def _become_owner(self) -> None:
        """Take the link: build and start the service, then serve the relay socket. If any step fails, everything
        started here is closed and link.lock is given back before the error is raised, so the next call, in this
        process or another, can try again (F37). A held lock with no service and no socket would refuse every
        process on this host until a restart."""
        service = None
        try:
            self._lock_fh.seek(0)
            self._lock_fh.truncate()
            self._lock_fh.write(str(os.getpid()))
            self._lock_fh.flush()
            service = self._make_service()
            await service.start()
            sock = self.dir / SOCK_FILE
            sock.unlink(missing_ok=True)                   # stale from an owner that died
            old = os.umask(0o177)
            try:
                self._relay_server = await asyncio.start_unix_server(self._relay_accept, str(sock))
            finally:
                os.umask(old)
            with contextlib.suppress(NotImplementedError):  # older Linux: the umask above already made it 0600
                os.chmod(sock, 0o600, follow_symlinks=False)  # the socket itself, never what a link in its place names
        except BaseException:
            await self._give_back(service)
            raise
        self.service = service
        # A normal exit removes the socket. A hard stop (SIGTERM, SIGHUP, or Hermes's gateway, which always ends with
        # os._exit) skips atexit and leaves it: harmless (owner-only, nothing listens), and the next owner replaces it.
        if not self._exit_hook:
            self._exit_hook = True
            atexit.register(self._remove_socket)
        logger.info("tether host: this process (pid %d) owns the link", os.getpid())

    async def _give_back(self, service: Any) -> None:
        """Undo a failed _become_owner: close what it started and release link.lock (best effort, never raises)."""
        if self._relay_server is not None:
            self._relay_server.close()
            self._relay_server = None
            (self.dir / SOCK_FILE).unlink(missing_ok=True)     # only a socket this process just made
        if service is not None:
            try:
                await service.close()
            except Exception:  # noqa: BLE001
                logger.warning("tether host: closing a service that failed to start failed", exc_info=True)
        if self._lock_fh is not None:
            self._lock_fh.close()                              # releases the lock
            self._lock_fh = None

    async def _relay_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async def relay_call(args: dict, body: bytes):
            return await self.service.call(args["device"], args["kind"], args.get("args") or {}, body,
                                           float(args.get("timeout") or 120),
                                           expect_fp=str(args.get("expect_fp") or ""))

        async def relay_status(args: dict, body: bytes):
            return {"rows": self.service.status()}, b""

        peer = Peer(reader, writer, name="tether relay client",
                    handlers={"relay_call": relay_call, "relay_status": relay_status},
                    on_close=self._clients.discard)
        self._clients.add(peer)
        await peer.serve()

    def _remove_socket(self) -> None:
        """At a normal exit: remove link.sock if this process still owns the link (never another owner's socket)."""
        if self.service is not None:
            (self.dir / SOCK_FILE).unlink(missing_ok=True)

    async def close(self) -> None:
        if self._peer:
            await self._peer.close()
            self._peer = None
        if self._relay_server:
            self._relay_server.close()
            self._relay_server = None
        for peer in list(self._clients):
            await peer.close()
        if self.service:
            await self.service.close()
            self.service = None
            (self.dir / SOCK_FILE).unlink(missing_ok=True)
        if self._lock_fh:
            self._lock_fh.close()                          # releases the lock
            self._lock_fh = None

    # ---------- what callers use (same as HostService) ----------
    async def call(self, device: str, kind: str, args: dict[str, Any], body: bytes = b"",
                   timeout: float = 120.0, expect_fp: str = "") -> tuple[dict[str, Any], bytes]:
        await self.ensure()
        if self.service is not None:
            return await self.service.call(device, kind, args, body, timeout, expect_fp=expect_fp)
        return await self._peer.call("relay_call", {"device": device, "kind": kind, "args": args,
                                                    "timeout": timeout, "expect_fp": expect_fp}, body,
                                     timeout + RELAY_SLACK_S)

    async def list_devices(self, may_own: bool = True) -> list[dict[str, Any]]:
        await self.ensure(may_own)
        if self.service is not None:
            return self.service.status()
        data, _ = await self._peer.call("relay_status", {}, b"", 15)
        return data["rows"]
