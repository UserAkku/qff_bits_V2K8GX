"""Arithmetic in GF(2^128) using the bit-reflected convention of AES-GCM (NIST SP 800-38D).

Field elements are Python ints holding a 16-byte block read big-endian, so the
spec's bit 0 is the integer's most significant bit. Using GCM's exact
convention lets us validate the field multiply against any AES-GCM
implementation (see ``tests/crypto/test_gf128.py``) and keeps the Python and
TypeScript Wegman-Carter MACs byte-for-byte interoperable.
"""

from __future__ import annotations

BLOCK_BYTES = 16
_R = 0xE1 << 120  # x^128 + x^7 + x^2 + x + 1, reflected
_MASK = (1 << 128) - 1


def block_to_int(block: bytes) -> int:
    if len(block) != BLOCK_BYTES:
        raise ValueError(f"expected a {BLOCK_BYTES}-byte block, got {len(block)}")
    return int.from_bytes(block, "big")


def int_to_block(value: int) -> bytes:
    return (value & _MASK).to_bytes(BLOCK_BYTES, "big")


def gf128_mul(x: int, y: int) -> int:
    """Multiply two field elements (SP 800-38D, Algorithm 1)."""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def _blocks(data: bytes) -> list[int]:
    """Split ``data`` into 16-byte blocks, zero-padding the last one."""
    out = []
    for start in range(0, len(data), BLOCK_BYTES):
        chunk = data[start : start + BLOCK_BYTES]
        out.append(int.from_bytes(chunk.ljust(BLOCK_BYTES, b"\x00"), "big"))
    return out


class PolyHash:
    """Incremental polynomial evaluation at H over 16-byte blocks.

    ``digest(final)`` closes the input with one extra block (which must encode
    the total length, so zero padding is unambiguous) without disturbing the
    running state, so one transcript can be tagged at several checkpoints.
    """

    def __init__(self, h: int):
        self._h = h
        self._x = 0
        self._buffer = b""
        self.length = 0

    def update(self, data: bytes) -> None:
        self.length += len(data)
        data = self._buffer + data
        full = len(data) - len(data) % BLOCK_BYTES
        x = self._x
        for start in range(0, full, BLOCK_BYTES):
            x = gf128_mul(x ^ int.from_bytes(data[start : start + BLOCK_BYTES], "big"), self._h)
        self._x = x
        self._buffer = data[full:]

    def digest(self, final_block: int) -> int:
        x = self._x
        if self._buffer:
            x = gf128_mul(
                x ^ int.from_bytes(self._buffer.ljust(BLOCK_BYTES, b"\x00"), "big"), self._h
            )
        return gf128_mul(x ^ final_block, self._h)


def ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    """GHASH_H(A, C): polynomial evaluation of the padded blocks of A || C || len(A) || len(C) at H.

    As a keyed hash family indexed by ``h`` this is epsilon-almost-XOR-universal
    with epsilon = (L + 1) / 2^128 for inputs of at most L blocks, which is
    what the Wegman-Carter construction in :mod:`qkd.crypto.wc_mac` relies on.
    """
    x = 0
    for block in _blocks(aad) + _blocks(ciphertext):
        x = gf128_mul(x ^ block, h)
    lengths = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    return gf128_mul(x ^ lengths, h)
