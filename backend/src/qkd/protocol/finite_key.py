"""Finite-key secret key length for BB84, after Tomamichel, Lim, Gisin, Renner (2012).

Protocol of the paper: n key bits are measured in the X basis and k bits in the
Z basis (the parameter-estimation sample), with X chosen with probability
p_x = 1 / (1 + sqrt(k / n)) to minimise the signals needed. The protocol aborts
when the Z-sample error exceeds Q_tol, and the extracted key may have length

    l <= n [ q - h(Q_tol + mu(eps)) ] - 2 log2(1 / (2 eps_bar)) - leak_EC - log2(2 / eps_cor)

for any eps, eps_bar > 0 with 2 eps + eps_bar <= eps_sec, where
mu(eps) = sqrt( (n + k) / (n k) * (k + 1) / k * ln(1 / eps) ), q = 1 for ideal
BB84 states, and h is the binary entropy truncated at 1 above 1/2
(Nature Communications 3, 634 (2012), Theorem 2 / Eq. S3-S4; main text Eq. 2 is
the choice eps = eps_sec / 4, eps_bar = eps_sec / 2).

``leak_EC`` counts every bit disclosed during error correction, and the
log2(2 / eps_cor) term pays for the verification hash (ceil(log2(1/eps_cor))
bits) that is also revealed.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil, floor, log, log2, sqrt

import numpy as np


def h2(x: float) -> float:
    """Binary entropy, truncated to 1 for x >= 1/2 (as in the paper)."""
    if x <= 0:
        return 0.0
    if x >= 0.5:
        return 1.0
    return float(-x * log2(x) - (1 - x) * log2(1 - x))


def mu(n: int, k: int, eps: float) -> float:
    """Statistical deviation of the phase error estimated from k samples."""
    return sqrt((n + k) / (n * k) * (k + 1) / k * log(1 / eps))


def x_basis_probability(n: int, k: int) -> float:
    """Probability p_x of choosing the key (X) basis so n key and k test bits arrive together."""
    return 1 / (1 + sqrt(k / n))


@dataclass(frozen=True)
class KeyLengthBreakdown:
    length: int  # secret bits that may be extracted (0 if none)
    n: int
    k: int
    q_tol: float
    mu: float
    eps: float  # eps used inside mu
    eps_bar: float  # smoothing slack used in the leftover-hash step
    phase_error_bound: float  # Q_tol + mu
    entropy_term: float  # n [1 - h(Q_tol + mu)]
    leak_ec: int
    correctness_cost: float  # log2(2 / eps_cor)
    secrecy_cost: float  # 2 log2(1 / (2 eps_bar))
    extra_cost: float  # additional conservative bits (e.g. union bound over leak values)
    asymptotic: float  # n [1 - h(Q_tol)] - leak_EC, for comparison


def key_length(
    n: int,
    k: int,
    q_tol: float,
    leak_ec: int,
    eps_sec: float,
    eps_cor: float,
    q: float = 1.0,
    extra_cost: float = 0.0,
    split: float | None = None,
) -> KeyLengthBreakdown:
    """Largest allowed key length. ``split`` fixes eps = split * eps_sec / 2 (default: optimise it)."""
    if n <= 0 or k <= 0:
        raise ValueError("n and k must be positive")

    def evaluate(s: float) -> tuple[float, float, float, float, float]:
        eps = s * eps_sec / 2  # 2 eps + eps_bar = eps_sec  =>  eps_bar = (1 - s) eps_sec
        eps_bar = (1 - s) * eps_sec
        m = mu(n, k, eps)
        value = (
            n * (q - h2(q_tol + m))
            - 2 * log2(1 / (2 * eps_bar))
            - leak_ec
            - log2(2 / eps_cor)
            - extra_cost
        )
        return value, eps, eps_bar, m, q_tol + m

    grid = [split] if split is not None else list(np.linspace(0.02, 0.98, 193))
    best = max((evaluate(s) for s in grid), key=lambda r: r[0])
    value, eps, eps_bar, m, bound = best
    return KeyLengthBreakdown(
        length=max(0, floor(value)),
        n=n,
        k=k,
        q_tol=q_tol,
        mu=m,
        eps=eps,
        eps_bar=eps_bar,
        phase_error_bound=bound,
        entropy_term=n * (q - h2(bound)),
        leak_ec=leak_ec,
        correctness_cost=log2(2 / eps_cor),
        secrecy_cost=2 * log2(1 / (2 * eps_bar)),
        extra_cost=extra_cost,
        asymptotic=n * (q - h2(q_tol)) - leak_ec,
    )


def paper_formula_length(
    n: int, k: int, q_tol: float, leak_ec: int, eps_sec: float, eps_cor: float
) -> int:
    """Main-text Eq. (2): the fixed choice eps = eps_sec / 4, eps_bar = eps_sec / 2."""
    m = sqrt((n + k) / (n * k) * (k + 1) / k * log(4 / eps_sec))
    value = n * (1 - h2(q_tol + m)) - leak_ec - log2(2 / (eps_sec**2 * eps_cor))
    return max(0, floor(value))


def union_bound_bits(max_leak: int) -> int:
    """Conservative cost of choosing l after seeing the realised leak_EC.

    The theorem is stated for a pre-declared leak_EC. Taking the realised value
    (one of at most ``max_leak + 1`` possibilities, all public) is a union bound
    over that many protocols, which we pay for by lengthening 2 log2(1/eps) by
    2 log2(max_leak + 1) bits.
    """
    return 2 * ceil(log2(max_leak + 1)) if max_leak > 0 else 0
