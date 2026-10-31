"""Eve's quantum-channel attacks, restricted to operations quantum mechanics allows.

An attack never reads Alice's bit or basis directly: it only gets the photon
(a qubit) and may measure it, entangle it with her own probe qubit, and send
something on to Bob. The only classical information an attack may use is
what is public anyway (for example, the basis Alice announces during sifting,
which Eve can wait for before measuring a stored probe).

Each attack assigns every signal an *action code* (0 = left alone) and knows
how to append its gates for that code to a signal's circuit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum

import numpy as np
from numpy.typing import NDArray
from qiskit import QuantumCircuit
from qiskit.circuit import Clbit

from qkd.quantum.bases import BREIDBART_ANGLE, Basis, rotate_from_z, rotate_to_z


class QuantumAttack(ABC):
    """Base class: plan which signals to touch, then build the gates per action code."""

    name: str = "attack"
    n_actions: int = 1  # action codes are 0..n_actions-1, 0 meaning "not attacked"
    uses_probe: bool = False  # needs an ancilla qubit in Eve's lab

    @abstractmethod
    def plan(self, n: int, rng: np.random.Generator) -> NDArray[np.int64]:
        """Choose an action code for each of ``n`` signals."""

    @abstractmethod
    def apply(
        self,
        qc: QuantumCircuit,
        photon: int,
        probe: int | None,
        action: int,
        announced: Basis,
        eve_bit: Clbit,
    ) -> None:
        """Append Eve's operation for ``action``; ``announced`` is the basis Alice will announce later."""

    @abstractmethod
    def guess(
        self, action: NDArray[np.int64], outcome: NDArray[np.int8], announced: NDArray[np.int8]
    ) -> NDArray[np.int8]:
        """Eve's best guess of Alice's bit per signal once bases are public (-1 = no information)."""

    def describe(self) -> dict[str, object]:
        return {"name": self.name}


class EveBasis(IntEnum):
    RANDOM = -1
    Z = 0
    X = 1
    Y = 2
    BREIDBART = 3


@dataclass
class InterceptResend(QuantumAttack):
    """Measure the photon in some basis and send Bob a fresh photon in the observed state.

    With a random Z/X basis on every signal this is the textbook attack: Eve
    picks the wrong basis half the time, and then Bob's sifted bit is wrong
    half the time, so QBER = fraction / 4.
    """

    fraction: float = 1.0
    basis: EveBasis = EveBasis.RANDOM
    six_state: bool = False  # draw random bases from Z, X, Y instead of Z, X

    name = "intercept_resend"
    n_actions = 5  # 0 none, 1 Z, 2 X, 3 Y, 4 Breidbart

    def plan(self, n: int, rng: np.random.Generator) -> NDArray[np.int64]:
        attacked = rng.random(n) < self.fraction
        if self.basis == EveBasis.RANDOM:
            bases = rng.integers(0, 3 if self.six_state else 2, n)
        else:
            bases = np.full(n, int(self.basis))
        return np.where(attacked, bases + 1, 0).astype(np.int64)

    def apply(self, qc, photon, probe, action, announced, eve_bit) -> None:
        if action == 4:
            qc.ry(-BREIDBART_ANGLE, photon)
            qc.measure(photon, eve_bit)
            qc.ry(BREIDBART_ANGLE, photon)
            return
        basis = Basis(action - 1)
        rotate_to_z(qc, photon, basis)
        qc.measure(photon, eve_bit)
        rotate_from_z(qc, photon, basis)

    def guess(self, action, outcome, announced):
        measured_basis = action - 1
        exact = (action > 0) & ((measured_basis == announced) | (action == 4))
        return np.where(exact, outcome, -1).astype(np.int8)

    def describe(self) -> dict[str, object]:
        return {"name": self.name, "fraction": self.fraction, "basis": self.basis.name.lower()}
