"""Randomness source for protocol parties: OS entropy for live sessions, seeded PRNG for experiments.

Live sessions draw every secret bit, basis choice and hash seed from
``os.urandom`` (a CSPRNG). Experiments pass a seed so figures reproduce
bit-for-bit; seeded mode is *not* secure and the UI never offers it for chats.
"""

from __future__ import annotations

import os

import numpy as np
from numpy.typing import NDArray


class Randomness:
    def __init__(self, seed: int | None = None, stream: int = 0):
        """``stream`` selects an independent sub-stream of ``seed`` (Alice 0, Bob 1, the link 2, ...)."""
        self.seeded = seed is not None
        self._rng = np.random.default_rng([seed, stream]) if seed is not None else None

    def bytes(self, n: int) -> bytes:
        if self._rng is not None:
            return self._rng.bytes(n)
        return os.urandom(n)

    def bits(self, n: int) -> NDArray[np.uint8]:
        if self._rng is not None:
            return self._rng.integers(0, 2, n, dtype=np.uint8)
        raw = np.frombuffer(os.urandom((n + 7) // 8), dtype=np.uint8)
        return np.unpackbits(raw)[:n].copy()

    def uniform(self, n: int) -> NDArray[np.float64]:
        """n floats uniform in [0, 1) with 53 random bits each."""
        if self._rng is not None:
            return self._rng.random(n)
        raw = np.frombuffer(os.urandom(8 * n), dtype=np.uint64) >> np.uint64(11)
        return raw.astype(np.float64) * 2.0**-53

    def choice_bits(self, n: int, p_one: float) -> NDArray[np.uint8]:
        """n bits, each 1 with probability ``p_one``."""
        return (self.uniform(n) < p_one).astype(np.uint8)

    def seed_int(self) -> int:
        return int.from_bytes(self.bytes(8), "big")
