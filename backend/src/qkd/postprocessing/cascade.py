"""Cascade information reconciliation (Brassard & Salvail, EUROCRYPT 1993).

Bob corrects his sifted key towards Alice's by comparing parities of blocks in
several shuffled orderings of the key. Each parity Alice reveals is one bit of
information handed to Eve; ``CascadeBob.leaked_bits`` counts them exactly so
privacy amplification can subtract them.

The two parties are separate objects so the protocol engine can carry every
round over the authenticated classical channel::

    while queries := bob.next_queries():
        bob.receive(alice.answer(queries))

All BINARY searches of a round run side by side, so the number of rounds grows
with log2(block size) per pass rather than with the number of errors.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil

import numpy as np
from numpy.typing import NDArray

Bits = NDArray[np.uint8]
Perm = NDArray[np.int64]

# Floor for the QBER used to size the first-pass blocks when the estimate is ~0.
MIN_QBER = 0.002
DEFAULT_PASSES = 4


@dataclass(frozen=True)
class ParityQuery:
    """Parity of positions [start, end) of the key taken in the shuffled order of ``pass_index``."""

    pass_index: int
    start: int
    end: int


@dataclass
class PassStats:
    block_size: int
    parities: int = 0
    corrected: int = 0


def block_sizes(qber: float, n: int, passes: int = DEFAULT_PASSES) -> list[int]:
    """Original Cascade schedule: k1 = ceil(0.73 / Q), doubling every pass."""
    k1 = max(4, ceil(0.73 / max(qber, MIN_QBER)))
    return [max(1, min(n, k1 << i)) for i in range(passes)]


def shuffles(seed: int, n: int, passes: int) -> list[Perm]:
    """Public per-pass permutations; both parties derive them from Alice's announced seed."""
    rng = np.random.default_rng(seed)
    return [rng.permutation(n).astype(np.int64) for _ in range(passes)]


class CascadeAlice:
    """Holds the reference key and answers parity queries in O(1) via prefix XORs."""

    def __init__(self, key: Bits, perms: list[Perm]):
        self._prefix: list[Bits] = []
        for perm in perms:
            prefix = np.zeros(key.size + 1, dtype=np.uint8)
            np.bitwise_xor.accumulate(key[perm], out=prefix[1:])
            self._prefix.append(prefix)
        self.revealed = 0

    def answer(self, queries: list[ParityQuery]) -> list[int]:
        self.revealed += len(queries)
        return [
            int(self._prefix[q.pass_index][q.end] ^ self._prefix[q.pass_index][q.start])
            for q in queries
        ]


@dataclass(eq=False)
class _Search:
    """One BINARY bisection; invariant: Alice's and Bob's parities of [start, end) differ."""

    pass_index: int
    block: int
    start: int
    end: int
    alice_parity: int

    @property
    def mid(self) -> int:
        return (self.start + self.end) // 2


class CascadeBob:
    """Drives the reconciliation and corrects Bob's copy of the key in place."""

    def __init__(self, key: Bits, perms: list[Perm], sizes: list[int]):
        if len(perms) != len(sizes):
            raise ValueError("need one permutation per pass")
        self.key = key.astype(np.uint8, copy=True)
        self.n = int(key.size)
        self._perms = perms
        self._positions = [np.argsort(p) for p in perms]  # key index -> index in pass order
        self._sizes = sizes
        self._alice_blocks: list[Bits] = []
        self._bob_blocks: list[Bits] = []
        self._searches: list[_Search] = []
        self._searching: set[tuple[int, int]] = set()
        self._pending: str | None = None  # what the outstanding queries were for
        self._pass = -1
        self.stats = [PassStats(k) for k in sizes]
        self.rounds = 0
        self.leaked_bits = 0
        self.corrected_positions: list[int] = []

    # -- protocol -------------------------------------------------------------

    def next_queries(self) -> list[ParityQuery]:
        """Queries for the next round; an empty list means reconciliation is finished."""
        if self._pending is not None:
            raise RuntimeError("receive() the previous answers first")
        self._settle_searches()
        if self._searches:
            queries = [ParityQuery(s.pass_index, s.start, s.mid) for s in self._searches]
            self._pending = "search"
        elif self._pass + 1 < len(self._sizes) and self.n > 0:
            self._start_pass()
            k = self._sizes[self._pass]
            queries = [
                ParityQuery(self._pass, start, min(start + k, self.n))
                for start in range(0, self.n, k)
            ]
            self._pending = "blocks"
        else:
            return []
        self.rounds += 1
        self.leaked_bits += len(queries)
        for q in queries:
            self.stats[q.pass_index].parities += 1
        return queries

    def receive(self, answers: list[int]) -> None:
        if self._pending == "blocks":
            alice = np.asarray(answers, dtype=np.uint8)
            self._alice_blocks.append(alice)
            for block in np.flatnonzero(alice != self._bob_blocks[self._pass]):
                self._open_search(self._pass, int(block))
        elif self._pending == "search":
            if len(answers) != len(self._searches):
                raise ValueError("one answer per outstanding search expected")
            current, self._searches = self._searches, []
            for search, alice_left in zip(current, answers, strict=True):
                alice_right = search.alice_parity ^ alice_left
                if self._parity(search.pass_index, search.start, search.mid) != alice_left:
                    search.end, search.alice_parity = search.mid, alice_left
                elif self._parity(search.pass_index, search.mid, search.end) != alice_right:
                    search.start, search.alice_parity = search.mid, alice_right
                else:  # another search already fixed the error in this range
                    self._close_search(search)
                    continue
                self._searches.append(search)
        else:
            raise RuntimeError("no outstanding queries")
        self._pending = None

    @property
    def done(self) -> bool:
        return self._pending is None and not self._searches and self._pass + 1 >= len(self._sizes)

    # -- internals --------------------------------------------------------------

    def _parity(self, pass_index: int, start: int, end: int) -> int:
        return int(np.bitwise_xor.reduce(self.key[self._perms[pass_index][start:end]]))

    def _start_pass(self) -> None:
        self._pass += 1
        k = self._sizes[self._pass]
        ordered = self.key[self._perms[self._pass]].astype(np.int64)
        starts = np.arange(0, self.n, k)
        self._bob_blocks.append((np.add.reduceat(ordered, starts) & 1).astype(np.uint8))

    def _block_range(self, pass_index: int, block: int) -> tuple[int, int]:
        k = self._sizes[pass_index]
        return block * k, min((block + 1) * k, self.n)

    def _open_search(self, pass_index: int, block: int) -> None:
        if (pass_index, block) in self._searching:
            return
        start, end = self._block_range(pass_index, block)
        alice = int(self._alice_blocks[pass_index][block])
        self._searching.add((pass_index, block))
        self._searches.append(_Search(pass_index, block, start, end, alice))

    def _close_search(self, search: _Search) -> None:
        self._searching.discard((search.pass_index, search.block))
        # The block may still hold an odd number of errors (e.g. 3 -> 2 -> ...).
        if (
            self._bob_blocks[search.pass_index][search.block]
            != self._alice_blocks[search.pass_index][search.block]
        ):
            self._open_search(search.pass_index, search.block)

    def _settle_searches(self) -> None:
        """Resolve single-bit searches (flipping the bit) and drop stale ones until all need a query."""
        changed = True
        while changed:
            changed = False
            for search in list(self._searches):
                mismatch = (
                    self._parity(search.pass_index, search.start, search.end) != search.alice_parity
                )
                if mismatch and search.end - search.start > 1:
                    continue
                self._searches.remove(search)
                if mismatch:
                    self._flip(int(self._perms[search.pass_index][search.start]), search.pass_index)
                self._close_search(search)
                changed = True

    def _flip(self, index: int, found_in_pass: int) -> None:
        """Correct bit ``index`` and let the correction cascade into every pass seen so far."""
        self.key[index] ^= 1
        self.corrected_positions.append(index)
        self.stats[found_in_pass].corrected += 1
        for p in range(self._pass + 1):
            block = int(self._positions[p][index]) // self._sizes[p]
            self._bob_blocks[p][block] ^= 1
            if (
                p < len(self._alice_blocks)
                and self._bob_blocks[p][block] != self._alice_blocks[p][block]
            ):
                self._open_search(p, block)


@dataclass(frozen=True)
class CascadeResult:
    corrected_key: Bits
    leaked_bits: int
    rounds: int
    passes: list[PassStats]


def reconcile_locally(
    alice_key: Bits, bob_key: Bits, qber: float, seed: int, passes: int = DEFAULT_PASSES
) -> CascadeResult:
    """Run both parties in-process (experiments and tests; the protocol engine uses the classes)."""
    n = int(alice_key.size)
    perms = shuffles(seed, n, passes)
    alice = CascadeAlice(alice_key, perms)
    bob = CascadeBob(bob_key, perms, block_sizes(qber, n, passes))
    while queries := bob.next_queries():
        bob.receive(alice.answer(queries))
    return CascadeResult(bob.key, bob.leaked_bits, bob.rounds, bob.stats)
