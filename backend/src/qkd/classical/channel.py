"""The public classical channel between Alice and Bob.

Everything sent here is public: the protocol assumes Eve reads every message.
Eve may also *change* messages in flight (``tamper``); the channel does not
stop her. Instead, both parties feed every message they send or receive into
a :class:`~qkd.auth.transcript.TranscriptAuthenticator`, and a Wegman-Carter
tag exchange at each checkpoint reveals any modification before a key is
accepted. That is exactly the "authenticated classical channel" assumption of
QKD security proofs, implemented rather than assumed.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import numpy as np
from numpy.typing import NDArray

Role = Literal["alice", "bob"]


def other(role: Role) -> Role:
    return "bob" if role == "alice" else "alice"


@dataclass(frozen=True)
class Message:
    seq: int
    sender: Role
    kind: str
    payload: dict[str, Any]

    def encode(self) -> bytes:
        """Canonical bytes: what gets authenticated and what counts as public data."""
        body = {"seq": self.seq, "sender": self.sender, "kind": self.kind, "payload": self.payload}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    @property
    def size_bytes(self) -> int:
        return len(self.encode())


class ProtocolAbort(Exception):
    """Raised on both sides when a session ends without a key."""

    def __init__(self, reason: str, stage: str, detail: dict[str, Any] | None = None):
        super().__init__(f"{stage}: {reason}")
        self.reason = reason
        self.stage = stage
        self.detail = detail or {}


Tap = Callable[[Message], None]
Tamper = Callable[[Message], Message]


@dataclass
class ClassicalChannel:
    """Two in-order queues (one inbox per party) that anyone may read and Eve may alter."""

    taps: list[Tap] = field(default_factory=list)
    tamper: Tamper | None = None
    timeout_s: float = 60.0

    def __post_init__(self) -> None:
        self._inbox: dict[Role, asyncio.Queue[Message]] = {
            "alice": asyncio.Queue(),
            "bob": asyncio.Queue(),
        }
        self._seq = 0
        self.bytes_sent = 0
        self.messages_sent = 0

    async def send(self, sender: Role, kind: str, payload: dict[str, Any]) -> Message:
        message = Message(self._seq, sender, kind, payload)
        self._seq += 1
        on_wire = self.tamper(message) if self.tamper else message
        self.bytes_sent += on_wire.size_bytes
        self.messages_sent += 1
        for tap in self.taps:
            tap(on_wire)
        await self._inbox[other(sender)].put(on_wire)
        return message

    async def receive(self, receiver: Role, kind: str | tuple[str, ...]) -> Message:
        kinds = (kind,) if isinstance(kind, str) else kind
        kind = "/".join(kinds)
        try:
            message = await asyncio.wait_for(self._inbox[receiver].get(), self.timeout_s)
        except TimeoutError as exc:
            raise ProtocolAbort("the other party stopped responding", kind) from exc
        if message.kind == "abort":
            payload = message.payload
            raise ProtocolAbort(
                payload.get("reason", "aborted by peer"), payload.get("stage", kind), payload
            )
        if message.kind not in kinds:
            raise ProtocolAbort(f"expected '{kind}' but received '{message.kind}'", kind)
        return message


# -- payload helpers -----------------------------------------------------------


def pack_bits(bits: NDArray[np.integer]) -> dict[str, Any]:
    """Bit array (0/1 values) as {"n": length, "b64": packed bytes}."""
    arr = np.asarray(bits, dtype=np.uint8)
    return {"n": int(arr.size), "b64": base64.b64encode(np.packbits(arr).tobytes()).decode()}


def unpack_bits(obj: dict[str, Any]) -> NDArray[np.uint8]:
    raw = np.frombuffer(base64.b64decode(obj["b64"]), dtype=np.uint8)
    return np.unpackbits(raw)[: int(obj["n"])].astype(np.uint8)


def pack_symbols(values: NDArray[np.integer]) -> dict[str, Any]:
    """Small non-negative integers (e.g. bases 0..2) as one byte each."""
    arr = np.asarray(values, dtype=np.uint8)
    return {"n": int(arr.size), "b64": base64.b64encode(arr.tobytes()).decode()}


def unpack_symbols(obj: dict[str, Any]) -> NDArray[np.uint8]:
    return np.frombuffer(base64.b64decode(obj["b64"]), dtype=np.uint8)[: int(obj["n"])].copy()
