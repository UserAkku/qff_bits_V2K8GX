"""One-time pad over bytes. A pad must never be used twice (the key manager enforces this)."""

from __future__ import annotations


def xor_bytes(data: bytes, pad: bytes) -> bytes:
    if len(pad) != len(data):
        raise ValueError(f"one-time pad must match the data length ({len(pad)} != {len(data)})")
    if not data:
        return b""
    return (int.from_bytes(data, "big") ^ int.from_bytes(pad, "big")).to_bytes(len(data), "big")
