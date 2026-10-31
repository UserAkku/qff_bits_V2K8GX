"""Wegman-Carter authentication of the whole classical transcript, checked at checkpoints.

Each party absorbs every message it sends or receives (length-prefixed
canonical encodings, in channel order) into a polynomial hash over GF(2^128)
keyed by a secret H drawn once per session. At checkpoint c, Alice sends
tag_A = poly_H(T || final(c, alice)) xor P_{c,A} and Bob replies with the same
for his side, each verifying the other's tag against its *own* view T of the
conversation. If Eve changed, dropped, injected or reordered anything, the
two views differ and a tag fails, except with probability at most L / 2^128
per tag for a transcript of L blocks.

H is reused across the session's tags while every pad P is used once: that is
the Wegman-Carter construction, and it is why a session burns
16 + 32 * checkpoints bytes of authentication key.
"""

from __future__ import annotations

import hmac
from math import ceil

from qkd.classical.channel import Message, Role
from qkd.crypto.gf128 import BLOCK_BYTES, PolyHash, block_to_int, int_to_block

DEFAULT_CHECKPOINTS = 2


def session_auth_bytes(checkpoints: int = DEFAULT_CHECKPOINTS) -> int:
    return BLOCK_BYTES + 2 * BLOCK_BYTES * checkpoints


class TranscriptAuthenticator:
    def __init__(self, key: bytes, checkpoints: int = DEFAULT_CHECKPOINTS):
        if len(key) != session_auth_bytes(checkpoints):
            raise ValueError(f"need {session_auth_bytes(checkpoints)} bytes of authentication key")
        self.checkpoints = checkpoints
        self._hash = PolyHash(block_to_int(key[:BLOCK_BYTES]))
        self._pads = [
            block_to_int(key[start : start + BLOCK_BYTES])
            for start in range(BLOCK_BYTES, len(key), BLOCK_BYTES)
        ]
        self.messages = 0

    def absorb(self, message: Message) -> None:
        encoded = message.encode()
        self._hash.update(len(encoded).to_bytes(4, "big") + encoded)
        self.messages += 1

    def tag(self, checkpoint: int, role: Role) -> bytes:
        if not 0 <= checkpoint < self.checkpoints:
            raise ValueError("no such checkpoint")
        is_bob = int(role == "bob")
        final = ((self._hash.length * 8) << 64) | (checkpoint << 1) | is_bob
        return int_to_block(self._hash.digest(final) ^ self._pads[2 * checkpoint + is_bob])

    def verify(self, checkpoint: int, role: Role, tag: bytes) -> bool:
        return hmac.compare_digest(self.tag(checkpoint, role), tag)

    @property
    def forgery_bound(self) -> float:
        """Per-tag bound L / 2^128 for the transcript absorbed so far."""
        return (ceil(self._hash.length / BLOCK_BYTES) + 1) / 2.0**128
