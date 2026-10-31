"""Session parameters shared by both parties (public, agreed in advance).

Following the finite-key protocol of Tomamichel et al. (2012), the key is made
from n bits measured in the X basis and the channel is tested on k bits
measured in the Z basis; signals are sent in chunks until both counts are met.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil, log2

from qkd.auth.transcript import DEFAULT_CHECKPOINTS, session_auth_bytes
from qkd.protocol.finite_key import h2, x_basis_probability


@dataclass(frozen=True)
class SessionParams:
    n_key: int = 16_384  # sifted X-basis bits that feed the key
    k_test: int = 8_192  # sifted Z-basis bits revealed to estimate the error
    chunk: int = 20_000  # signals per quantum transmission round
    max_signals: int = 4_000_000  # give up after this many (long, lossy links)
    q_tol: float = 0.07  # abort when the Z-sample error exceeds this (Q_tol)
    eps_sec: float = 1e-10
    eps_cor: float = 1e-15
    cascade_passes: int = 4
    leak_budget_factor: float = 1.5  # abort when EC leaks more than factor * n * h(q_tol)
    min_key_bits: int = 128  # abort rather than deliver a key shorter than this
    auth_checkpoints: int = DEFAULT_CHECKPOINTS
    preview_signals: int = 32  # signals shown step by step in the UI

    def __post_init__(self) -> None:
        if self.n_key < 256 or self.k_test < 256:
            raise ValueError("n_key and k_test must be at least 256")
        if not 0 < self.q_tol < 0.5:
            raise ValueError("q_tol must be in (0, 0.5)")
        if not (0 < self.eps_sec < 1 and 0 < self.eps_cor < 1):
            raise ValueError("epsilons must be in (0, 1)")
        if self.chunk < 100 or self.max_signals < self.chunk:
            raise ValueError("invalid chunk / max_signals")

    @property
    def p_x(self) -> float:
        """Probability of the X (key) basis; the Z (test) basis gets the rest."""
        return x_basis_probability(self.n_key, self.k_test)

    @property
    def verification_bits(self) -> int:
        """Tag length t so a wrong key passes verification with probability <= 2^-t <= eps_cor."""
        return ceil(log2(1 / self.eps_cor))

    @property
    def leak_budget(self) -> int:
        return ceil(self.leak_budget_factor * self.n_key * h2(self.q_tol))

    @property
    def auth_key_bytes(self) -> int:
        return session_auth_bytes(self.auth_checkpoints)

    @property
    def auth_refill_bits(self) -> int:
        """Key set aside from every successful session to pay back the authentication budget."""
        return 8 * self.auth_key_bytes
