"""One live link between host and device: multiplexed calls over the framed TLS stream (design §4).

Frames: ``call{id, kind, args, chunked}`` → ``result{id, ok, data, error, chunked}``; ``chunk`` frames carry big
bodies interleaved with other traffic; ``cancel{id}``; ``ping``/``pong`` keepalive; ``event`` one-way.
Either side can call the other (the device sends ``announce`` events; the host calls ``exec`` etc.).
"""
from __future__ import annotations

import asyncio
import itertools
import logging
import time
from typing import Any, Awaitable, Callable, Optional

from . import frames

logger = logging.getLogger(__name__)

Handler = Callable[[dict[str, Any], bytes], Awaitable[tuple[dict[str, Any], bytes]]]
PING_EVERY_S = 20.0
DEAD_AFTER_S = 60.0


class RemoteError(Exception):
    """The other side ran the call and reported an error (its message is safe to show)."""


class Peer:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, name: str,
                 handlers: dict[str, Handler], on_event: Optional[Callable[[dict, bytes], None]] = None,
                 on_close: Optional[Callable[["Peer"], None]] = None) -> None:
        self.reader, self.writer, self.name = reader, writer, name
        self.handlers, self.on_event, self.on_close = handlers, on_event, on_close
        self._lock = asyncio.Lock()
        self._ids = itertools.count(1)
        self._pending: dict[str, asyncio.Future] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._chunks = frames.Reassembler()
        self._partial: dict[str, dict[str, Any]] = {}
        self.last_seen = time.monotonic()
        self.closed = asyncio.Event()

    # ---------- sending ----------
    async def _send(self, header: dict[str, Any], body: bytes = b"") -> None:
        if len(body) <= frames.MAX_BODY:
            await frames.write_frame(self.writer, {**header, "chunked": False}, body, self._lock)
            return
        await frames.write_frame(self.writer, {**header, "chunked": True}, b"", self._lock)
        for h, part in frames.split_body(header["id"], body):
            await frames.write_frame(self.writer, h, part, self._lock)   # other frames may interleave

    async def call(self, kind: str, args: dict[str, Any], body: bytes = b"",
                   timeout: float = 120.0) -> tuple[dict[str, Any], bytes]:
        if self.closed.is_set():
            raise ConnectionError(f"{self.name} is not connected")
        cid = f"{'h' if self.name else 'x'}{next(self._ids)}"
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[cid] = fut
        try:
            await self._send({"t": "call", "id": cid, "kind": kind, "args": args, "deadline": timeout}, body)
            header, data = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            await self._safe_send({"t": "cancel", "id": cid})
            raise TimeoutError(f"{kind} on {self.name} took longer than {timeout:.0f}s") from None
        except asyncio.CancelledError:                 # interrupted on the host: stop it on the device too
            await asyncio.shield(self._safe_send({"t": "cancel", "id": cid}))
            raise
        finally:
            self._pending.pop(cid, None)
        if not header.get("ok"):
            raise RemoteError(header.get("error") or f"{kind} failed on {self.name}")
        return header.get("data") or {}, data

    async def event(self, kind: str, data: dict[str, Any], body: bytes = b"") -> None:
        await self._safe_send({"t": "event", "id": f"e{next(self._ids)}", "kind": kind, "data": data}, body)

    async def _safe_send(self, header: dict[str, Any], body: bytes = b"") -> None:
        try:
            await self._send(header, body)
        except Exception:  # noqa: BLE001 - the link is going away; the reader loop reports it
            pass

    # ---------- receiving ----------
    async def serve(self) -> None:
        pinger = asyncio.create_task(self._keepalive())
        try:
            while True:
                header, body = await frames.read_frame(self.reader)
                self.last_seen = time.monotonic()
                t = header.get("t")
                if t == "chunk":
                    data = self._chunks.add(header, body)
                    if data is not None:
                        self._dispatch(self._partial.pop(header["id"]), data)
                    continue
                if header.get("chunked"):
                    self._partial[header["id"]] = header
                    continue
                self._dispatch(header, body)
        except (ConnectionError, asyncio.IncompleteReadError, frames.FrameError) as e:
            logger.info("tether: link %s closed: %s", self.name, e)
        finally:
            pinger.cancel()
            await self.close()

    def _dispatch(self, header: dict[str, Any], body: bytes) -> None:
        t = header.get("t")
        if t == "result":
            fut = self._pending.get(header.get("id"))
            if fut and not fut.done():
                fut.set_result((header, body))
        elif t == "call":
            self._tasks[header["id"]] = asyncio.create_task(self._run_handler(header, body))
        elif t == "cancel":
            task = self._tasks.pop(header.get("id"), None)
            if task:
                task.cancel()
        elif t == "ping":
            asyncio.create_task(self._safe_send({"t": "pong", "id": header.get("id", "p")}))
        elif t == "event" and self.on_event:
            try:
                self.on_event(header, body)
            except Exception:  # noqa: BLE001
                logger.warning("tether: event handler failed", exc_info=True)

    async def _run_handler(self, header: dict[str, Any], body: bytes) -> None:
        cid, kind = header["id"], header.get("kind")
        handler = self.handlers.get(kind)
        try:
            if handler is None:
                raise RemoteError(f"this side does not handle {kind!r}")
            data, out = await handler(header.get("args") or {}, body)
            await self._send({"t": "result", "id": cid, "ok": True, "data": data}, out)
        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001 - report the failure to the caller, keep the link
            msg = str(e) if isinstance(e, (RemoteError, PermissionError, ValueError, TimeoutError,
                                           ConnectionError)) else \
                f"{type(e).__name__}: {e}"
            await self._safe_send({"t": "result", "id": cid, "ok": False, "error": msg})
        finally:
            self._tasks.pop(cid, None)

    async def _keepalive(self) -> None:
        while not self.closed.is_set():
            await asyncio.sleep(PING_EVERY_S)
            if time.monotonic() - self.last_seen > DEAD_AFTER_S:
                logger.info("tether: link %s silent for %.0fs; closing", self.name, DEAD_AFTER_S)
                await self.close()
                return
            await self._safe_send({"t": "ping", "id": "p"})

    async def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError(f"{self.name} disconnected"))
        for task in self._tasks.values():
            task.cancel()
        try:
            self.writer.close()
        except Exception:  # noqa: BLE001
            pass
        if self.on_close:
            try:
                self.on_close(self)
            except Exception:  # noqa: BLE001
                pass
