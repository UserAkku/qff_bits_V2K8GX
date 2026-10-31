from math import log, log2, sqrt

import pytest

from qkd.protocol.finite_key import (
    h2,
    key_length,
    mu,
    paper_formula_length,
    union_bound_bits,
    x_basis_probability,
)


def test_binary_entropy_values_and_truncation():
    assert h2(0) == 0 and h2(0.5) == 1 and h2(0.9) == 1
    assert h2(0.11) == pytest.approx(0.4999, abs=1e-3)  # Shor-Preskill threshold region
    assert h2(0.25) == pytest.approx(0.8113, abs=1e-4)


def test_mu_matches_paper_expression_and_shrinks_with_k():
    n, k, eps = 10_000, 5_000, 1e-10 / 4
    by_hand = sqrt((n + k) / (n * k) * (k + 1) / k * log(1 / eps))
    assert mu(n, k, eps) == pytest.approx(by_hand)
    assert by_hand == pytest.approx(0.0856, abs=5e-4)
    assert mu(n, 10 * k, eps) < mu(n, k, eps)
    assert mu(n, k, 1e-5) < mu(n, k, 1e-15)


def test_optimised_length_is_at_least_the_papers_fixed_choice():
    for n, k, q in [(20_000, 10_000, 0.02), (100_000, 50_000, 0.05), (5_000, 5_000, 0.01)]:
        leak = int(1.16 * n * h2(q))
        fixed = paper_formula_length(n, k, q, leak, 1e-10, 1e-15)
        best = key_length(n, k, q, leak, 1e-10, 1e-15)
        assert best.length >= fixed
        assert best.length - fixed < 0.02 * best.length  # same theorem, only a better eps split


def test_fixed_split_reproduces_main_text_equation():
    n, k, q, leak = 30_000, 15_000, 0.03, 4_000
    eps_sec, eps_cor = 1e-10, 1e-15
    fixed = key_length(
        n, k, q, leak, eps_sec, eps_cor, split=0.5
    )  # eps = eps_sec/4, eps_bar = eps_sec/2
    assert fixed.length == paper_formula_length(n, k, q, leak, eps_sec, eps_cor)
    assert fixed.eps == pytest.approx(eps_sec / 4) and fixed.eps_bar == pytest.approx(eps_sec / 2)
    assert fixed.secrecy_cost == pytest.approx(2 * log2(1 / eps_sec))
    assert fixed.correctness_cost == pytest.approx(log2(2 / eps_cor))


def test_approaches_asymptotic_rate_as_blocks_grow():
    q = 0.02
    rates = []
    for n in (1_000, 10_000, 100_000, 1_000_000):
        k = n // 2
        result = key_length(n, k, q, 0, 1e-10, 1e-15)
        rates.append(result.length / n)
    assert rates == sorted(rates)  # monotone improvement
    assert rates[-1] == pytest.approx(1 - h2(q), abs=0.06)
    assert rates[0] < 0.2  # tiny blocks are nearly useless at eps = 1e-10


def test_no_key_when_noise_or_blocks_are_too_bad():
    assert key_length(2_000, 1_000, 0.08, int(1.2 * 2_000 * h2(0.08)), 1e-10, 1e-15).length == 0
    assert (
        key_length(100_000, 50_000, 0.11, int(1.16 * 100_000 * h2(0.11)), 1e-10, 1e-15).length == 0
    )


def test_extra_cost_reduces_the_key_one_for_one():
    base = key_length(20_000, 10_000, 0.02, 3_000, 1e-10, 1e-15)
    cut = key_length(20_000, 10_000, 0.02, 3_000, 1e-10, 1e-15, extra_cost=30)
    assert base.length - cut.length in (29, 30, 31)


def test_basis_probability_balances_counts():
    n, k = 16_384, 8_192
    px = x_basis_probability(n, k)
    assert px == pytest.approx(1 / (1 + sqrt(0.5)))
    # expected matched counts px^2 : pz^2 equal n : k
    assert px**2 / (1 - px) ** 2 == pytest.approx(n / k)


def test_union_bound_is_small_but_nonzero():
    assert union_bound_bits(0) == 0
    assert 20 <= union_bound_bits(20_000) <= 40
