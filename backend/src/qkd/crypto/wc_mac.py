"""Wegman-Carter one-time MAC: tag = GHASH_H(aad, message) xor P.

H (hash key) and P (tag pad) are 128-bit blocks of QKD key, both used once.
GHASH is epsilon-almost-XOR-universal with epsilon = L / 2^128 for inputs of at
most L blocks (padded AAD + padded message + length block), so a forger who
sees one tagged message succeeds with probability at most L / 2^128 regardless
of computing power. Security is information-theoretic *only if* H and P are
uniformly random and secret, which in this project they are not physically
(they come from a simulated QKD link).

Because the tag equals an AES-GCM tag when H = AES_K(0^128) and P = AES_K(J0),
any AES-GCM implementation doubles as a reference for test vectors.
"""

from __future__ import annotations

import hmac
from math import ceil

from qkd.crypto.gf128 import BLOCK_BYTES, block_to_int, ghash, int_to_block

TAG_BYTES = 16
KEY_BYTES = 2 * BLOCK_BYTES  # H || P


def wc_tag(key: bytes, aad: bytes, message: bytes) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError(f"Wegman-Carter key must be {KEY_BYTES} bytes (H || P)")
    h = block_to_int(key[:BLOCK_BYTES])
    pad = block_to_int(key[BLOCK_BYTES:])
    return int_to_block(ghash(h, aad, message) ^ pad)


def wc_verify(key: bytes, aad: bytes, message: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(wc_tag(key, aad, message), tag)


def hashed_blocks(aad_len: int, message_len: int) -> int:
    return ceil(aad_len / BLOCK_BYTES) + ceil(message_len / BLOCK_BYTES) + 1


def forgery_bound(aad_len: int, message_len: int) -> float:
    """Upper bound on a single substitution attack succeeding."""
    return hashed_blocks(aad_len, message_len) / 2.0**128
