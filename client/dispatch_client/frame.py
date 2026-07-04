"""Length-prefixed JSON framing for the dispatch wire protocol.

Matches the Go reference (internal/wire): each frame is a 4-byte big-endian
uint32 length prefix followed by that many bytes of UTF-8 JSON. The JSON is an
envelope ``{"v": "0.1", "type": <msg>, "id": <req-id>, "body": {...}}``. A
zero-length frame is illegal; frames are capped at 4 MiB.
"""

from __future__ import annotations

import json
import socket
import struct
from typing import Any

CONTRACT_VERSION = "0.1"
MAX_FRAME_BYTES = 4 << 20  # 4 MiB, matches wire.MaxFrameBytes


class FrameError(Exception):
    """A framing- or envelope-level protocol violation."""


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise. Raises ConnectionError on clean EOF."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def write_frame(sock: socket.socket, payload: bytes) -> None:
    """Write one length-prefixed frame."""
    if not payload:
        raise FrameError("refusing to write zero-length frame")
    if len(payload) > MAX_FRAME_BYTES:
        raise FrameError(f"frame of {len(payload)} bytes exceeds max {MAX_FRAME_BYTES}")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def read_frame(sock: socket.socket) -> bytes:
    """Read one length-prefixed frame's payload bytes.

    Raises ConnectionError on a clean EOF at a frame boundary (the peer closed
    the connection), FrameError on a protocol violation.
    """
    prefix = _recv_exact(sock, 4)
    (n,) = struct.unpack(">I", prefix)
    if n == 0:
        raise FrameError("zero-length frame")
    if n > MAX_FRAME_BYTES:
        raise FrameError(f"frame of {n} bytes exceeds max {MAX_FRAME_BYTES}")
    return _recv_exact(sock, n)


def encode_envelope(req_id: str, msg_type: str, body: dict[str, Any]) -> bytes:
    """Marshal an envelope to frame bytes (no length prefix).

    Keys are emitted in the reference order (v, type, id, body); the Go server
    decodes strictly by field name, so order is cosmetic but kept for parity.
    """
    env = {"v": CONTRACT_VERSION, "type": msg_type, "id": req_id, "body": body}
    return json.dumps(env, separators=(",", ":")).encode("utf-8")


def decode_envelope(frame: bytes) -> dict[str, Any]:
    """Decode and validate an envelope frame into {v, type, id, body}."""
    try:
        env = json.loads(frame.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FrameError(f"envelope decode: {e}") from e
    if not isinstance(env, dict):
        raise FrameError("envelope is not a JSON object")
    if env.get("v") != CONTRACT_VERSION:
        raise FrameError(f"envelope version {env.get('v')!r}, want {CONTRACT_VERSION!r}")
    if not isinstance(env.get("type"), str):
        raise FrameError("envelope missing type")
    if not isinstance(env.get("id"), str):
        raise FrameError("envelope missing id")
    body = env.get("body")
    if not isinstance(body, dict):
        raise FrameError("envelope missing body object")
    return env


def write_message(sock: socket.socket, req_id: str, msg_type: str, body: dict[str, Any]) -> None:
    """Frame and write a typed message."""
    write_frame(sock, encode_envelope(req_id, msg_type, body))


def read_message(sock: socket.socket) -> dict[str, Any]:
    """Read one frame and decode its envelope."""
    return decode_envelope(read_frame(sock))
