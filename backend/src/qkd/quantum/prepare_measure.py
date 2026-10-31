"""Quantum link for prepare-and-measure protocols (BB84, six-state).

This module plays the role of *physics*: it receives Alice's preparations and
Bob's measurement settings, runs the Qiskit circuits (with channel noise and
Eve's attack inserted between them), applies loss and detector effects, and
hands each party only what their own lab would observe:

* Bob gets click/no-click and his measured bit per time slot;
* Eve gets the outcomes of her own measurements;
* nobody gets Alice's bits or bases from here (she announces bases herself,
  over the classical channel, during sifting).

In a simulation this component necessarily knows everything; that is the
central caveat of the security model (docs/security-model.md).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister

from qkd.quantum.attacks import QuantumAttack
from qkd.quantum.bases import Basis, measure_in, prepare
from qkd.quantum.channel import ChannelModel
from qkd.quantum.executor import BatchedExecutor, BatchResult

N_BASES = 3


def encode(
    bit: NDArray, alice_basis: NDArray, bob_basis: NDArray, action: NDArray
) -> NDArray[np.int64]:
    return (bit + 2 * (alice_basis + N_BASES * (bob_basis + N_BASES * action))).astype(np.int64)


def decode(code: int) -> tuple[int, Basis, Basis, int]:
    bit, rest = code % 2, code // 2
    alice, rest = rest % N_BASES, rest // N_BASES
    bob, action = rest % N_BASES, rest // N_BASES
    return bit, Basis(alice), Basis(bob), action


@dataclass
class BobObservation:
    detected: NDArray[np.bool_]
    bits: NDArray[np.int8]  # -1 where no click
    double_clicks: int


@dataclass
class EveObservation:
    action: NDArray[np.int64]  # 0 where the signal was not touched
    outcome: NDArray[np.int8]  # Eve's raw measurement result, -1 where none

    def guesses(self, attack: QuantumAttack, announced_bases: NDArray[np.int8]) -> NDArray[np.int8]:
        return attack.guess(self.action, self.outcome, announced_bases)


@dataclass
class Transmission:
    bob: BobObservation
    eve: EveObservation | None
    batch: BatchResult
    arrived: int


class PrepareMeasureLink:
    def __init__(
        self, channel: ChannelModel, attack: QuantumAttack | None = None, seed: int | None = None
    ):
        """``seed`` makes runs reproducible (experiments, tests); leave it None for live sessions."""
        self.channel = channel
        self.attack = attack
        self.executor = BatchedExecutor(seed=seed, simulator=channel.simulator())
        self.rng = np.random.default_rng(None if seed is None else seed + 1)

    def circuit(self, code: int) -> QuantumCircuit:
        """The full single-signal experiment for one configuration code."""
        bit, alice_basis, bob_basis, action = decode(code)
        photon = QuantumRegister(1, "photon")
        registers: list = [photon]
        if self.attack is not None and self.attack.uses_probe:
            registers.append(QuantumRegister(1, "probe"))
        bob = ClassicalRegister(1, "bob")
        registers.append(bob)
        eve = ClassicalRegister(1, "eve") if self.attack is not None else None
        if eve is not None:
            registers.append(eve)
        qc = QuantumCircuit(*registers, name=f"signal_{code}")

        prepare(qc, 0, bit, alice_basis)
        qc.barrier(label="Alice → channel")
        if self.attack is not None and action:
            probe = 1 if self.attack.uses_probe else None
            self.attack.apply(qc, 0, probe, action, alice_basis, eve[0])
            qc.barrier(label="Eve")
        self.channel.apply(qc, 0)
        qc.barrier(label="→ Bob")
        measure_in(qc, 0, bob_basis, bob[0])
        return qc

    def transmit(
        self,
        alice_bits: NDArray[np.int8],
        alice_bases: NDArray[np.int8],
        bob_bases: NDArray[np.int8],
    ) -> Transmission:
        n = alice_bits.size
        if not (alice_bases.size == bob_bases.size == n):
            raise ValueError("bits and bases must have the same length")
        action = self.attack.plan(n, self.rng) if self.attack else np.zeros(n, dtype=np.int64)
        arrived = self.rng.random(n) < self.channel.eta
        # Only signals that reach Bob or that Eve touches need a quantum simulation.
        active = arrived | (action > 0)
        idx = np.flatnonzero(active)
        registers = ["bob", "eve"] if self.attack else ["bob"]
        codes = encode(alice_bits[idx], alice_bases[idx], bob_bases[idx], action[idx])
        batch = self.executor.run(codes, self.circuit, registers)

        outcomes = np.full(n, -1, dtype=np.int8)
        outcomes[idx] = batch.outcomes["bob"]
        detected, bits, doubles = self.channel.detect(outcomes, arrived, self.rng)

        eve = None
        if self.attack is not None:
            eve_outcome = np.full(n, -1, dtype=np.int8)
            eve_outcome[idx] = batch.outcomes["eve"]
            eve_outcome[action == 0] = -1
            eve = EveObservation(action=action, outcome=eve_outcome)
        return Transmission(BobObservation(detected, bits, doubles), eve, batch, int(arrived.sum()))
