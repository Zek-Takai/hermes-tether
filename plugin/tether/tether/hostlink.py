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
        self._lock_fh.seek(0)
        self._lock_fh.truncate()
        self._lock_fh.write(str(os.getpid()))
        self._lock_fh.flush()
        service = self._make_service()
        await service.start()
        sock = self.dir / SOCK_FILE
        sock.unlink(missing_ok=True)                       # stale from an owner that died
        old = os.umask(0o177)
        try:
            self._relay_server = await asyncio.start_unix_server(self._relay_accept, str(sock))
        finally:
            os.umask(old)
        os.chmod(sock, 0o600)
        self.service = service
        logger.info("tether host: this process (pid %d) owns the link", os.getpid())

    async def _relay_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async def relay_call(args: dict, body: bytes):
            return await self.service.call(args["device"], args["kind"], args.get("args") or {}, body,
                                           float(args.get("timeout") or 120))

        async def relay_status(args: dict, body: bytes):
            return {"rows": self.service.status()}, b""

        peer = Peer(reader, writer, name="tether relay client",
                    handlers={"relay_call": relay_call, "relay_status": relay_status},
                    on_close=self._clients.discard)
        self._clients.add(peer)
        await peer.serve()

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
                   timeout: float = 120.0) -> tuple[dict[str, Any], bytes]:
        await self.ensure()
        if self.service is not None:
            return await self.service.call(device, kind, args, body, timeout)
        return await self._peer.call("relay_call", {"device": device, "kind": kind, "args": args,
                                                    "timeout": timeout}, body, timeout + RELAY_SLACK_S)

    async def list_devices(self, may_own: bool = True) -> list[dict[str, Any]]:
        await self.ensure(may_own)
        if self.service is not None:
            return self.service.status()
        data, _ = await self._peer.call("relay_status", {}, b"", 15)
        return data["rows"]
