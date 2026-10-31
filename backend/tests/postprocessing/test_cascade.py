import numpy as np
import pytest

from qkd.postprocessing.cascade import (
    CascadeAlice,
    CascadeBob,
    ParityQuery,
    block_sizes,
    reconcile_locally,
    shuffles,
)


def binary_entropy(p: float) -> float:
    return 0.0 if p <= 0 or p >= 1 else float(-p * np.log2(p) - (1 - p) * np.log2(1 - p))


def noisy_pair(n: int, qber: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    alice = rng.integers(0, 2, n, dtype=np.uint8)
    errors = (rng.random(n) < qber).astype(np.uint8)
    return alice, alice ^ errors


@pytest.mark.parametrize("qber", [0.005, 0.02, 0.05, 0.08, 0.11])
def test_reconciles_all_errors(qber):
    for seed in range(5):
        alice, bob = noisy_pair(10_000, qber, seed)
        result = reconcile_locally(alice, bob, qber, seed=seed)
        assert np.array_equal(result.corrected_key, alice)


@pytest.mark.parametrize("qber", [0.01, 0.03, 0.05])
def test_efficiency_is_close_to_shannon_limit(qber):
    alice, bob = noisy_pair(100_000, qber, 11)
    actual = float(np.mean(alice ^ bob))
    result = reconcile_locally(alice, bob, actual, seed=3)
    f = result.leaked_bits / (alice.size * binary_entropy(actual))
    assert 1.0 < f < 1.3  # original 4-pass Cascade sits around 1.12-1.22


def test_leakage_equals_parities_alice_revealed():
    alice, bob = noisy_pair(5_000, 0.04, 2)
    perms = shuffles(9, alice.size, 4)
    a = CascadeAlice(alice, perms)
    b = CascadeBob(bob, perms, block_sizes(0.04, alice.size))
    while queries := b.next_queries():
        b.receive(a.answer(queries))
    assert b.leaked_bits == a.revealed == sum(s.parities for s in b.stats)
    assert sum(s.corrected for s in b.stats) == len(b.corrected_positions)
    assert np.array_equal(b.key, alice)


def test_identical_keys_only_cost_top_level_parities():
    alice, _ = noisy_pair(4_096, 0.0, 5)
    result = reconcile_locally(alice, alice.copy(), 0.01, seed=1)
    sizes = block_sizes(0.01, alice.size)
    assert result.leaked_bits == sum(-(-alice.size // k) for k in sizes)
    assert all(p.corrected == 0 for p in result.passes)


def test_rounds_grow_logarithmically_not_with_error_count():
    alice, bob = noisy_pair(200_000, 0.03, 4)
    result = reconcile_locally(alice, bob, 0.03, seed=4)
    errors = int(np.sum(alice ^ bob))
    assert errors > 5_000
    assert result.rounds < 150


def test_block_schedule_doubles_and_respects_key_length():
    assert block_sizes(0.073, 10_000) == [10, 20, 40, 80]
    assert block_sizes(0.0, 100)[-1] <= 100
    assert block_sizes(0.5, 10)[0] == 4


def test_queries_must_be_answered_before_next_round():
    _alice, bob = noisy_pair(100, 0.05, 1)
    perms = shuffles(0, 100, 4)
    b = CascadeBob(bob, perms, block_sizes(0.05, 100))
    first = b.next_queries()
    assert all(isinstance(q, ParityQuery) for q in first)
    with pytest.raises(RuntimeError):
        b.next_queries()
