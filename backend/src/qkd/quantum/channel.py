"""Physical model of the optical link: fibre loss, detectors, and polarization noise.

The split between quantum and classical simulation follows the physics:

* polarization noise acts on the qubit, so it is part of every Qiskit circuit
  (a misalignment rotation and/or a depolarizing channel), or comes from a
  real IBM device's noise model when ``device`` is set;
* loss, detector efficiency and dark counts decide *whether* a detector
  clicks, which is a classical random process applied after the circuit runs.

Detector model: Bob has one detector per outcome. A click on both (signal plus
a dark count on the other detector) is assigned a random bit, the standard
"squashing" treatment of double clicks.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from math import sin

import numpy as np
from numpy.typing import NDArray
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit_aer.noise import depolarizing_error

# Device noise profiles from qiskit-ibm-runtime's snapshots of real IBM backends.
DEVICE_PROFILES = (
    "FakeTorino",
    "FakeFez",
    "FakeKingston",
    "FakeMarrakesh",
    "FakeBrisbane",
    "FakeSherbrooke",
)


@dataclass(frozen=True)
class ChannelModel:
    length_km: float = 0.0
    attenuation_db_per_km: float = 0.2  # standard single-mode fibre at 1550 nm
    detector_efficiency: float = 1.0
    dark_count_prob: float = 0.0  # per detector, per time slot
    depolarizing: float = 0.0  # Qiskit depolarizing parameter p; adds QBER p/2
    misalignment_rad: float = 0.0  # polarization rotation theta; adds QBER sin^2(theta)
    device: str | None = None  # name from DEVICE_PROFILES to use real-device noise instead

    def __post_init__(self) -> None:
        for name in ("detector_efficiency", "dark_count_prob", "depolarizing"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1], got {value}")
        if self.length_km < 0 or self.attenuation_db_per_km < 0:
            raise ValueError("length and attenuation must be non-negative")
        if self.device is not None and self.device not in DEVICE_PROFILES:
            raise ValueError(f"unknown device profile {self.device!r}")

    @property
    def transmittance(self) -> float:
        """Fibre transmittance 10^(-alpha L / 10)."""
        return 10 ** (-self.attenuation_db_per_km * self.length_km / 10)

    @property
    def eta(self) -> float:
        """Probability that a single photon sent by Alice makes Bob's detector click."""
        return self.transmittance * self.detector_efficiency

    @property
    def intrinsic_qber(self) -> float:
        """QBER from polarization noise alone (no Eve, no dark counts)."""
        if self.device is not None:
            return float("nan")  # depends on the device calibration; measured, not predicted
        rotated = sin(self.misalignment_rad) ** 2
        return (1 - self.depolarizing) * rotated + self.depolarizing / 2

    def apply(self, qc: QuantumCircuit, qubit: int) -> None:
        """Append the in-flight polarization noise to a signal qubit."""
        if self.misalignment_rad:
            qc.ry(2 * self.misalignment_rad, qubit)
        if self.depolarizing and self.device is None:
            qc.append(depolarizing_error(self.depolarizing, 1), [qubit])

    def simulator(self) -> AerSimulator:
        return _device_simulator(self.device) if self.device else AerSimulator()

    def detect(
        self, outcomes: NDArray[np.int8], arrived: NDArray[np.bool_], rng: np.random.Generator
    ) -> tuple[NDArray[np.bool_], NDArray[np.int8], int]:
        """Combine arrivals, quantum outcomes and dark counts into Bob's clicks.

        Returns (detected mask, bit per signal or -1, number of double clicks).
        """
        n = outcomes.size
        signal = arrived & (outcomes >= 0)
        click0 = (signal & (outcomes == 0)) | (rng.random(n) < self.dark_count_prob)
        click1 = (signal & (outcomes == 1)) | (rng.random(n) < self.dark_count_prob)
        detected = click0 | click1
        double = click0 & click1
        bits = np.where(click1, 1, 0).astype(np.int8)
        bits[double] = rng.integers(0, 2, int(double.sum()), dtype=np.int8)
        bits[~detected] = -1
        return detected, bits, int(double.sum())


@cache
def _device_simulator(name: str) -> AerSimulator:
    from qiskit_ibm_runtime import fake_provider  # optional dependency (extra "ibm")

    return AerSimulator.from_backend(getattr(fake_provider, name)())
