"""Run many independent signals through Qiskit Aer by batching identical configurations.

Every signal in prepare-and-measure QKD is an independent experiment on one
photon (plus, at most, Eve's probe). Two signals with the same settings
(Alice's bit and basis, Bob's basis, Eve's action) are described by the same
small circuit, and running that circuit for k shots is *exactly* the same
random experiment as sending those k signals one after another. So we:

1. encode each signal's settings as an integer configuration code,
2. build one circuit per distinct code (typically 8-24 of them),
3. run all circuits in a single SamplerV2 call with shots = group size,
4. scatter the per-shot outcomes back to the signals of each group.

This keeps a full Qiskit simulation per signal while scaling to 10^6 signals
per session; ``tests/quantum/test_executor.py`` checks the equivalence
statistically against a wide one-qubit-per-signal circuit.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import numpy as np
from numpy.typing import NDArray
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit_aer.primitives import SamplerV2

Codes = NDArray[np.int64]


@dataclass
class BatchResult:
    """Per-signal outcomes for each named classical register (one bit per register)."""

    outcomes: dict[str, NDArray[np.int8]]
    circuits: dict[int, QuantumCircuit]
    shots_per_code: dict[int, int]
    seconds: float
    backend_name: str
    extra: dict[str, object] = field(default_factory=dict)


class BatchedExecutor:
    """Executes configuration-batched circuits on an Aer simulator (ideal or device-noise)."""

    def __init__(self, seed: int | None = None, simulator: AerSimulator | None = None):
        self._simulator = simulator or AerSimulator()
        self._seed = seed
        self._runs = 0
        self._layouts: dict[int, list[int]] = {}

    @property
    def backend_name(self) -> str:
        return str(self._simulator.name)

    def run(
        self,
        codes: Codes,
        build: Callable[[int], QuantumCircuit],
        registers: Sequence[str],
    ) -> BatchResult:
        """Run ``build(code)`` once per distinct code with as many shots as signals carry it."""
        started = time.perf_counter()
        n = int(codes.size)
        outcomes = {name: np.full(n, -1, dtype=np.int8) for name in registers}
        if n == 0:
            return BatchResult(outcomes, {}, {}, 0.0, self.backend_name)

        unique, inverse, counts = np.unique(codes, return_inverse=True, return_counts=True)
        circuits = {int(code): build(int(code)) for code in unique}
        width = max(c.num_qubits for c in circuits.values())
        compiled = transpile(
            list(circuits.values()),
            self._simulator,
            initial_layout=self._best_layout(width),
            optimization_level=0,
        )
        pubs = [
            (circuit, None, int(shots)) for circuit, shots in zip(compiled, counts, strict=True)
        ]

        run_options: dict[str, object] = {}
        if self._seed is not None:
            # Distinct but reproducible seeds per call of a seeded executor.
            run_options["seed_simulator"] = self._seed + 1_000_003 * self._runs
        self._runs += 1
        sampler = SamplerV2.from_backend(self._simulator)
        sampler.options.run_options = run_options
        results = sampler.run(pubs).result()

        order = np.argsort(inverse, kind="stable")  # signal indices grouped by code
        offsets = np.concatenate(([0], np.cumsum(counts)))
        for group, pub_result in enumerate(results):
            idx = order[offsets[group] : offsets[group + 1]]
            for name in registers:
                bits = getattr(pub_result.data, name).array[:, -1] & 1
                outcomes[name][idx] = bits.astype(np.int8)

        return BatchResult(
            outcomes=outcomes,
            circuits=circuits,
            shots_per_code={int(c): int(k) for c, k in zip(unique, counts, strict=True)},
            seconds=time.perf_counter() - started,
            backend_name=self.backend_name,
            extra={"layout": self._best_layout(width)},
        )

    def _best_layout(self, width: int) -> list[int] | None:
        """On a device-noise simulator, place the photon (and probe) on the best-calibrated qubits.

        A careful experimenter would not run on a qubit with 17% readout error
        just because it is called qubit 0, so we pick the qubit, or coupled
        pair, with the lowest summed readout and gate error.
        """
        if self._simulator.options.noise_model is None or width > 2:
            return None
        if width in self._layouts:
            return self._layouts[width]
        target = self._simulator.target

        def error(op: str, qargs: tuple[int, ...]) -> float:
            props = target[op].get(qargs) if op in target else None
            return props.error if props is not None and props.error is not None else 1.0

        def qubit_cost(q: int) -> float:
            return error("measure", (q,)) + error("sx", (q,))

        if width == 1:
            layout = [min(range(target.num_qubits), key=qubit_cost)]
        else:
            two_q = next(op for op in ("cz", "ecr", "cx") if op in target)
            pair = min(
                (qargs for qargs in target[two_q] if qargs is not None),
                key=lambda qargs: error(two_q, qargs) + qubit_cost(qargs[0]) + qubit_cost(qargs[1]),
            )
            layout = list(pair)
        self._layouts[width] = layout
        return layout
