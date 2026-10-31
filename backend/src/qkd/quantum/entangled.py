"""Entanglement-based link for E91 / BBM92: a source between Alice and Bob emits |Phi+> pairs.

Each party measures their photon along a direction in the x-z plane of the
Bloch sphere, at angle theta, by applying RY(-theta) and measuring Z. For
|Phi+> = (|00> + |11>)/sqrt(2) the correlation is E(a, b) = cos(a - b).

Ekert's settings (Bloch angles, i.e. twice the polarizer angle):

* Alice: a0 = 0,    a1 = pi/4, a2 = pi/2
* Bob:   b0 = pi/4, b1 = pi/2, b2 = 3pi/4

Pairs (a1, b0) and (a2, b1) measure along the same direction and give
perfectly correlated key bits. Pairs (a0, a2) x (b0, b2) enter the CHSH sum
S = E(a0,b0) - E(a0,b2) + E(a2,b0) + E(a2,b2) = 2 sqrt(2) for an ideal source,
while any local-realistic model (including a source Eve controls that sends
pre-determined states) obeys |S| <= 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import pi

import numpy as np
from numpy.typing import NDArray
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister

from qkd.quantum.attacks import QuantumAttack
from qkd.quantum.bases import Basis
from qkd.quantum.channel import ChannelModel
from qkd.quantum.executor import BatchedExecutor, BatchResult

ALICE_ANGLES = (0.0, pi / 4, pi / 2)
BOB_ANGLES = (pi / 4, pi / 2, 3 * pi / 4)
KEY_SETTINGS = ((1, 0), (2, 1))  # (alice, bob) setting pairs that share a direction
CHSH_TERMS = (((0, 0), 1), ((0, 2), -1), ((2, 0), 1), ((2, 2), 1))  # ((a, b), sign)
N_SETTINGS = 3


def encode(alice: NDArray, bob: NDArray, action: NDArray) -> NDArray[np.int64]:
    return (alice + N_SETTINGS * (bob + N_SETTINGS * action)).astype(np.int64)


def decode(code: int) -> tuple[int, int, int]:
    alice, rest = code % N_SETTINGS, code // N_SETTINGS
    return alice, rest % N_SETTINGS, rest // N_SETTINGS


@dataclass
class PartyObservation:
    detected: NDArray[np.bool_]
    bits: NDArray[np.int8]  # -1 where no click


@dataclass
class EntangledTransmission:
    alice: PartyObservation
    bob: PartyObservation
    eve_action: NDArray[np.int64] | None
    eve_outcome: NDArray[np.int8] | None
    batch: BatchResult


def chsh(
    alice_settings, bob_settings, alice_bits, bob_bits, valid
) -> tuple[float, dict[str, float]]:
    """Estimate S and the four correlators from coincidences (outcome 0 -> +1, 1 -> -1)."""
    correlators: dict[str, float] = {}
    s = 0.0
    for (a, b), sign in CHSH_TERMS:
        mask = valid & (alice_settings == a) & (bob_settings == b)
        if not mask.any():
            return float("nan"), correlators
        e = float(
            np.mean(
                (1 - 2 * alice_bits[mask].astype(np.int64))
                * (1 - 2 * bob_bits[mask].astype(np.int64))
            )
        )
        correlators[f"E(a{a},b{b})"] = e
        s += sign * e
    return s, correlators


class EntangledLink:
    """Entangled-pair source; Eve (if any) attacks the photon travelling to Bob."""

    def __init__(
        self, channel: ChannelModel, attack: QuantumAttack | None = None, seed: int | None = None
    ):
        if attack is not None and attack.uses_probe:
            raise ValueError("probe attacks are only modelled for prepare-and-measure links")
        self.channel = channel
        self.attack = attack
        self.executor = BatchedExecutor(seed=seed, simulator=channel.simulator())
        self.rng = np.random.default_rng(None if seed is None else seed + 1)

    def circuit(self, code: int) -> QuantumCircuit:
        alice_setting, bob_setting, action = decode(code)
        pair = QuantumRegister(2, "pair")  # pair[0] flies to Alice, pair[1] to Bob
        registers: list = [pair, ClassicalRegister(1, "alice"), ClassicalRegister(1, "bob")]
        if self.attack is not None:
            registers.append(ClassicalRegister(1, "eve"))
        qc = QuantumCircuit(*registers, name=f"pair_{code}")
        qc.h(0)
        qc.cx(0, 1)
        qc.barrier(label="source")
        if self.attack is not None and action:
            self.attack.apply(qc, 1, None, action, Basis.Z, qc.cregs[2][0])
            qc.barrier(label="Eve")
        self.channel.apply(qc, 0)
        self.channel.apply(qc, 1)
        qc.barrier(label="labs")
        qc.ry(-ALICE_ANGLES[alice_setting], 0)
        qc.ry(-BOB_ANGLES[bob_setting], 1)
        qc.measure(0, qc.cregs[0][0])
        qc.measure(1, qc.cregs[1][0])
        return qc

    def transmit(
        self, alice_settings: NDArray[np.int8], bob_settings: NDArray[np.int8]
    ) -> EntangledTransmission:
        n = alice_settings.size
        action = self.attack.plan(n, self.rng) if self.attack else np.zeros(n, dtype=np.int64)
        # Each photon of the pair crosses its own arm of the link (the source sits in the middle).
        arm = ChannelModel(
            length_km=self.channel.length_km / 2,
            attenuation_db_per_km=self.channel.attenuation_db_per_km,
            detector_efficiency=self.channel.detector_efficiency,
            dark_count_prob=self.channel.dark_count_prob,
        )
        arrived_a = self.rng.random(n) < arm.eta
        arrived_b = self.rng.random(n) < arm.eta
        active = arrived_a | arrived_b | (action > 0)
        idx = np.flatnonzero(active)
        registers = ["alice", "bob", "eve"] if self.attack else ["alice", "bob"]
        batch = self.executor.run(
            encode(alice_settings[idx], bob_settings[idx], action[idx]), self.circuit, registers
        )

        def observe(name: str, arrived: NDArray[np.bool_]) -> PartyObservation:
            outcomes = np.full(n, -1, dtype=np.int8)
            outcomes[idx] = batch.outcomes[name]
            detected, bits, _ = arm.detect(outcomes, arrived, self.rng)
            return PartyObservation(detected, bits)

        eve_outcome = None
        if self.attack is not None:
            eve_outcome = np.full(n, -1, dtype=np.int8)
            eve_outcome[idx] = batch.outcomes["eve"]
            eve_outcome[action == 0] = -1
        return EntangledTransmission(
            observe("alice", arrived_a),
            observe("bob", arrived_b),
            action if self.attack else None,
            eve_outcome,
            batch,
        )
