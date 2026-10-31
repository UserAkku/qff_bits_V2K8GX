"""Polarization bases as single-qubit circuits.

Physical picture (photon polarization) and qubit picture side by side:

======  ==============  ==================  ====================
basis   bit 0           bit 1               to measure, apply...
======  ==============  ==================  ====================
Z       |0>  vertical   |1>  horizontal     nothing
X       |+>  +45 deg    |->  -45 deg        H
Y       |+i> right-circ |-i> left-circ      S^dagger then H
======  ==============  ==================  ====================

BB84 uses Z and X; the six-state protocol adds Y. Measuring "in a basis" means
rotating that basis onto Z and measuring in the computational basis; resending
after a measurement (intercept-resend) applies the inverse rotation to the
collapsed state.
"""

from __future__ import annotations

from enum import IntEnum
from math import pi

from qiskit import QuantumCircuit


class Basis(IntEnum):
    Z = 0
    X = 1
    Y = 2

    @property
    def symbol(self) -> str:
        return "+x○"[self]


# Breidbart basis: halfway between Z and X on the Bloch sphere (pi/4 from each).
BREIDBART_ANGLE = pi / 4

GLYPHS = {
    (Basis.Z, 0): "↕",
    (Basis.Z, 1): "↔",
    (Basis.X, 0): "⤢",
    (Basis.X, 1): "⤡",
    (Basis.Y, 0): "↻",
    (Basis.Y, 1): "↺",
}


def prepare(qc: QuantumCircuit, qubit: int, bit: int, basis: Basis) -> None:
    """Append the gates that turn |0> into the BB84/six-state state (bit, basis)."""
    if bit:
        qc.x(qubit)
    if basis == Basis.X:
        qc.h(qubit)
    elif basis == Basis.Y:
        qc.h(qubit)
        qc.s(qubit)


def rotate_to_z(qc: QuantumCircuit, qubit: int, basis: Basis) -> None:
    """Map ``basis`` onto Z so a computational-basis measurement measures in ``basis``."""
    if basis == Basis.X:
        qc.h(qubit)
    elif basis == Basis.Y:
        qc.sdg(qubit)
        qc.h(qubit)


def rotate_from_z(qc: QuantumCircuit, qubit: int, basis: Basis) -> None:
    """Inverse of :func:`rotate_to_z`: re-prepare a measured qubit in ``basis``."""
    if basis == Basis.X:
        qc.h(qubit)
    elif basis == Basis.Y:
        qc.h(qubit)
        qc.s(qubit)


def measure_in(qc: QuantumCircuit, qubit: int, basis: Basis, clbit) -> None:
    rotate_to_z(qc, qubit, basis)
    qc.measure(qubit, clbit)
