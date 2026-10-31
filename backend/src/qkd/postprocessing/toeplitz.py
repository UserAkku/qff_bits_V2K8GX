"""Toeplitz hashing over GF(2): the 2-universal family used for privacy amplification.

A Toeplitz matrix T of shape (m, n) is fixed by a seed s of n + m - 1 bits via
T[i, j] = s[i - j + n - 1]. Multiplying T by the reconciled key x is a slice of
the full convolution of s and x, so the hash costs one FFT convolution instead
of m * n bit operations. The seed may be public; only its uniformity matters
for the leftover hash lemma.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray
from scipy.signal import fftconvolve

Bits = NDArray[np.uint8]

# Above this many input bits the float64 FFT could approach rounding trouble;
# we split the key into chunks and XOR the partial products instead.
_FFT_CHUNK = 1 << 20


def seed_length(n_in: int, n_out: int) -> int:
    return n_in + n_out - 1


def toeplitz_hash(seed: Bits, key: Bits, n_out: int) -> Bits:
    """Return T(seed) @ key mod 2 as ``n_out`` bits."""
    n_in = key.size
    if n_out <= 0:
        return np.zeros(0, dtype=np.uint8)
    if n_out > n_in:
        raise ValueError("privacy amplification cannot lengthen the key")
    if seed.size != seed_length(n_in, n_out):
        raise ValueError(f"seed must have {seed_length(n_in, n_out)} bits, got {seed.size}")

    out = np.zeros(n_out, dtype=np.int64)
    for start in range(0, n_in, _FFT_CHUNK):
        x = key[start : start + _FFT_CHUNK].astype(np.float64)
        # Columns start..start+len(x)-1 of T use seed indices offset by -start.
        lo = n_in - 1 - start - (x.size - 1)
        s = seed[lo : lo + n_out + x.size - 1].astype(np.float64)
        full = fftconvolve(s, x)
        part = full[x.size - 1 : x.size - 1 + n_out]
        rounded = np.rint(part)
        if np.max(np.abs(part - rounded), initial=0.0) > 0.25:
            raise ArithmeticError("FFT convolution lost integer precision")
        out += rounded.astype(np.int64)
    return (out & 1).astype(np.uint8)


def toeplitz_matrix(seed: Bits, n_in: int, n_out: int) -> Bits:
    """Dense matrix form, for tests and small visual examples only."""
    i = np.arange(n_out)[:, None]
    j = np.arange(n_in)[None, :]
    return seed[i - j + n_in - 1].astype(np.uint8)
