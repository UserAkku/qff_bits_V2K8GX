"""The quantum medium between Alice's and Bob's labs.

Alice hands in what she sends, Bob hands in his measurement bases; whoever
arrives second triggers the physics (Qiskit, in a worker thread so the event
loop stays responsive) and Bob receives only his own detector record. Alice
never learns what Bob measured and Bob never sees Alice's bits: they only
meet over the public classical channel.
"""

from __future__ import annotations

import asyncio

import numpy as np
from numpy.typing import NDArray

from qkd.quantum.prepare_measure import BobObservation, PrepareMeasureLink, Transmission


class QuantumMedium:
    def __init__(self, link: PrepareMeasureLink):
        self.link = link
        self.transmission: Transmission | None = None  # the simulator's omniscient record
        self._alice: tuple[NDArray[np.int8], NDArray[np.int8]] | None = None
        self._bob: NDArray[np.int8] | None = None
        self._done = asyncio.Event()
        self._failure: BaseException | None = None
        self._started = False

    async def alice_send(self, bits: NDArray[np.integer], bases: NDArray[np.integer]) -> None:
        self._alice = (bits.astype(np.int8), bases.astype(np.int8))
        await self._maybe_run()

    async def bob_measure(self, bases: NDArray[np.integer]) -> BobObservation:
        self._bob = bases.astype(np.int8)
        await self._maybe_run()
        await self._done.wait()
        if self._failure is not None:
            raise self._failure
        assert self.transmission is not None
        return self.transmission.bob

    async def _maybe_run(self) -> None:
        if self._alice is None or self._bob is None or self._started:
            return
        self._started = True
        try:
            bits, a_bases = self._alice
            self.transmission = await asyncio.to_thread(
                self.link.transmit, bits, a_bases, self._bob
            )
        except BaseException as exc:  # surfaced to Bob; Alice sees it when she next waits
            self._failure = exc
        finally:
            self._done.set()

    async def wait_done(self) -> None:
        await self._done.wait()
        if self._failure is not None:
            raise self._failure


class MediumHub:
    """One quantum medium per chunk of signals; both parties fetch the same instance by index."""

    def __init__(self, link: PrepareMeasureLink):
        self.link = link
        self.media: dict[int, QuantumMedium] = {}

    def medium(self, chunk: int) -> QuantumMedium:
        if chunk not in self.media:
            self.media[chunk] = QuantumMedium(self.link)
        return self.media[chunk]
