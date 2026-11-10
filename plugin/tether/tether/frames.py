"""Link framing (design §4): ``header_len(4) | body_len(4) | header JSON | body``.

Every frame belongs to one call id, so many calls share one link. Large bodies are sent as ``chunk``
frames interleaved with other traffic (see ``split_body``), so a big transfer never stalls a command.
"""
from __future__ import annotations

import asyncio
import json
import struct
from typing import Any, Iterator, Optional

PROTOCOL = {"major": 1, "minor": 0}
MAX_HEADER = 64 * 1024
MAX_BODY = 256 * 1024            # one frame; bigger payloads are chunked
MAX_CALL_BYTES = 64 * 1024 * 1024
_PREFIX = struct.Struct(">II")


class FrameError(Exception):
    pass


def encode(header: dict[str, Any], body: bytes = b"") -> bytes:
    h = json.dumps(header, separators=(",", ":")).encode()
    if len(h) > MAX_HEADER:
        raise FrameError(f"header too large ({len(h)} bytes)")
    if len(body) > MAX_BODY:
        raise FrameError(f"body too large for one frame ({len(body)} bytes); chunk it")
    return _PREFIX.pack(len(h), len(body)) + h + body


async def read_frame(reader: asyncio.StreamReader) -> tuple[dict[str, Any], bytes]:
    try:
        hlen, blen = _PREFIX.unpack(await reader.readexactly(_PREFIX.size))
    except asyncio.IncompleteReadError as e:
        raise ConnectionResetError("link closed") from e
    if hlen > MAX_HEADER or blen > MAX_BODY:
        raise FrameError(f"oversized frame (header {hlen}, body {blen})")
    header = json.loads(await reader.readexactly(hlen))
    if not isinstance(header, dict) or "t" not in header:
        raise FrameError("malformed frame header")
    body = await reader.readexactly(blen) if blen else b""
    return header, body


async def write_frame(writer: asyncio.StreamWriter, header: dict[str, Any], body: bytes = b"",
                      lock: Optional[asyncio.Lock] = None) -> None:
    data = encode(header, body)
    if lock is None:
        writer.write(data)
        await writer.drain()
        return
    async with lock:                       # one frame at a time on the wire; calls still interleave
        writer.write(data)
        await writer.drain()


def split_body(call_id: str, payload: bytes) -> Iterator[tuple[dict[str, Any], bytes]]:
    """Chunk frames for a payload larger than one frame."""
    if len(payload) > MAX_CALL_BYTES:
        raise FrameError(f"payload of {len(payload)} bytes exceeds the {MAX_CALL_BYTES}-byte call limit")
    total = max(1, -(-len(payload) // MAX_BODY))
    for seq in range(total):
        part = payload[seq * MAX_BODY:(seq + 1) * MAX_BODY]
        yield {"t": "chunk", "id": call_id, "seq": seq, "last": seq == total - 1}, part


class Reassembler:
    """Collects chunk frames per call id; returns the payload when the last chunk arrives."""

    def __init__(self) -> None:
        self._parts: dict[str, list[bytes]] = {}
        self._sizes: dict[str, int] = {}

    def add(self, header: dict[str, Any], body: bytes) -> Optional[bytes]:
        cid, seq = header["id"], header["seq"]
        parts = self._parts.setdefault(cid, [])
        if seq != len(parts):
            self.drop(cid)
            raise FrameError(f"chunk out of order for {cid}: got {seq}, expected {len(parts)}")
        parts.append(body)
        self._sizes[cid] = self._sizes.get(cid, 0) + len(body)
        if self._sizes[cid] > MAX_CALL_BYTES:
            self.drop(cid)
            raise FrameError(f"call {cid} exceeded {MAX_CALL_BYTES} bytes")
        if header.get("last"):
            data = b"".join(parts)
            self.drop(cid)
            return data
        return None

    def drop(self, cid: str) -> None:
        self._parts.pop(cid, None)
        self._sizes.pop(cid, None)


def check_hello(header: dict[str, Any]) -> None:
    """Protocol versioning (D17): same major required."""
    peer = header.get("protocol") or {}
    if header.get("t") != "hello" or peer.get("major") != PROTOCOL["major"]:
        raise FrameError(
            f"protocol mismatch: this side speaks {PROTOCOL['major']}.{PROTOCOL['minor']}, the other side "
            f"{peer.get('major')}.{peer.get('minor')}; update tether on both machines to the same version")
