"""The untrusted chat relay.

It routes opaque envelopes between users and keeps a log of exactly what it
saw. It has no access to any KME or key material (this module imports nothing
from ``server.kme``), so everything it can read is ciphertext, key IDs and
routing metadata, and everything it can do to a message is visible to the
recipient's integrity check. The ``mode`` switch turns the relay into an active
attacker for demonstrations: flip a ciphertext bit, replay the previous
message, or silently drop.
"""

from __future__ import annotations

import base64
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import WebSocket

from server.schemas import Envelope


class Relay:
    def __init__(self) -> None:
        self.mode = "honest"
        self.log: deque[dict[str, Any]] = deque(maxlen=500)
        self.inbox: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=200))
        self.sockets: dict[str, set[WebSocket]] = defaultdict(set)
        self._previous: dict[str, Any] | None = None
        self._counter = 0

    async def submit(self, envelope: Envelope) -> dict[str, Any]:
        data = envelope.model_dump(exclude_none=True)
        action = self.mode
        deliveries = [data]
        if action == "flip_ciphertext":
            deliveries = [_flip_first_bit(data)]
        elif action == "replay_last" and self._previous is not None:
            deliveries = [data, self._previous]
        elif action == "drop":
            deliveries = []
        self._previous = data

        self._counter += 1
        entry = {
            "n": self._counter,
            "t": time.time(),
            "relay_action": action,
            "delivered": len(deliveries),
            "envelope": data,  # what the wire carries; no plaintext exists here
        }
        self.log.append(entry)
        for item in deliveries:
            await self._deliver(item)
        return {"accepted": True, "relay_action": action, "delivered": len(deliveries)}

    async def _deliver(self, data: dict[str, Any]) -> None:
        recipient = data["recipient"]
        self.inbox[recipient].append(data)
        for socket in list(self.sockets[recipient]):
            try:
                await socket.send_json({"type": "message", "envelope": data})
            except Exception:
                self.sockets[recipient].discard(socket)

    async def connect(self, user: str, socket: WebSocket) -> None:
        await socket.accept()
        self.sockets[user].add(socket)
        for item in list(self.inbox[user]):
            await socket.send_json({"type": "message", "envelope": item, "backlog": True})

    def disconnect(self, user: str, socket: WebSocket) -> None:
        self.sockets[user].discard(socket)

    def messages_for(self, user: str) -> list[dict[str, Any]]:
        return list(self.inbox[user])

    def clear(self) -> None:
        self.log.clear()
        self.inbox.clear()
        self._previous = None


def _flip_first_bit(data: dict[str, Any]) -> dict[str, Any]:
    out = dict(data)
    raw = bytearray(base64.b64decode(out["ciphertext"]))
    if raw:
        raw[0] ^= 0x01
    out["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    return out
