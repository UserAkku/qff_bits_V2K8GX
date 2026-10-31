"""Statistical checks of the simulated quantum link against textbook predictions.

Tolerances are 5 standard errors of a binomial proportion, so with fixed seeds
these tests are deterministic and a real regression moves results far outside.
"""

import numpy as np
import pytest
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
from qiskit_aer import AerSimulator

from qkd.quantum.attacks import EveBasis, InterceptResend
from qkd.quantum.bases import Basis, measure_in, prepare
from qkd.quantum.channel import ChannelModel
from qkd.quantum.prepare_measure import PrepareMeasureLink, decode, encode


def run(n=40_000, channel=None, attack=None, seed=1, n_bases=2):
    rng = np.random.default_rng(seed)
    link = PrepareMeasureLink(channel or ChannelModel(), attack, seed=seed)
    bits = rng.integers(0, 2, n).astype(np.int8)
    a_bases = rng.integers(0, n_bases, n).astype(np.int8)
    b_bases = rng.integers(0, n_bases, n).astype(np.int8)
    return bits, a_bases, b_bases, link.transmit(bits, a_bases, b_bases), link


def sifted_qber(bits, a_bases, b_bases, tx, basis=None):
    keep = tx.bob.detected & (a_bases == b_bases)
    if basis is not None:
        keep &= a_bases == basis
    return float(np.mean(tx.bob.bits[keep] != bits[keep])), int(keep.sum())


def close(observed, expected, n):
    se = max(np.sqrt(expected * (1 - expected) / n), 1 / n)
    return abs(observed - expected) <= 5 * se


def test_codes_roundtrip():
    for bit in (0, 1):
        for a in range(3):
            for b in range(3):
                for action in range(5):
                    code = int(encode(np.array(bit), np.array(a), np.array(b), np.array(action)))
                    assert decode(code) == (bit, Basis(a), Basis(b), action)


def test_ideal_channel_has_no_errors_and_random_mismatches():
    bits, a, b, tx, _ = run()
    qber, n = sifted_qber(bits, a, b, tx)
    assert qber == 0.0 and n > 15_000
    mismatch = a != b
    assert close(float(np.mean(tx.bob.bits[mismatch] == bits[mismatch])), 0.5, int(mismatch.sum()))


def test_six_state_bases_are_consistent():
    bits, a, b, tx, _ = run(n=30_000, n_bases=3)
    qber, n = sifted_qber(bits, a, b, tx, basis=Basis.Y)
    assert qber == 0.0 and n > 2_500


@pytest.mark.parametrize("p", [0.04, 0.12])
def test_depolarizing_gives_qber_p_over_2(p):
    bits, a, b, tx, _ = run(channel=ChannelModel(depolarizing=p))
    qber, n = sifted_qber(bits, a, b, tx)
    assert close(qber, p / 2, n)


def test_misalignment_gives_sin_squared():
    theta = 0.25
    bits, a, b, tx, _ = run(channel=ChannelModel(misalignment_rad=theta))
    qber, n = sifted_qber(bits, a, b, tx)
    assert close(qber, np.sin(theta) ** 2, n)
    assert ChannelModel(misalignment_rad=theta).intrinsic_qber == pytest.approx(np.sin(theta) ** 2)


@pytest.mark.parametrize("fraction", [1.0, 0.4])
def test_intercept_resend_random_basis_gives_fraction_over_4(fraction):
    attack = InterceptResend(fraction=fraction)
    bits, a, b, tx, _ = run(attack=attack)
    qber, n = sifted_qber(bits, a, b, tx)
    assert close(qber, fraction / 4, n)
    # Eve learns exactly the bits where her basis matched the announced one.
    guesses = tx.eve.guesses(attack, a)
    known = guesses >= 0
    assert np.all(guesses[known] == bits[known])
    assert close(float(np.mean(known)), fraction / 2, bits.size)


def test_fixed_basis_attack_hides_in_key_basis_but_shows_in_test_basis():
    bits, a, b, tx, _ = run(attack=InterceptResend(basis=EveBasis.Z))
    z_qber, nz = sifted_qber(bits, a, b, tx, basis=Basis.Z)
    x_qber, nx = sifted_qber(bits, a, b, tx, basis=Basis.X)
    assert z_qber == 0.0 and nz > 5_000
    assert close(x_qber, 0.5, nx)


def test_breidbart_attack_trades_same_disturbance_for_more_information():
    attack = InterceptResend(basis=EveBasis.BREIDBART)
    bits, a, b, tx, _ = run(attack=attack)
    qber, n = sifted_qber(bits, a, b, tx)
    assert close(qber, 0.25, n)
    guesses = tx.eve.guesses(attack, a)
    assert close(float(np.mean(guesses == bits)), np.cos(np.pi / 8) ** 2, bits.size)


def test_loss_and_dark_counts():
    channel = ChannelModel(length_km=50, detector_efficiency=0.5)
    bits, a, b, tx, _ = run(channel=channel)
    assert close(float(np.mean(tx.bob.detected)), channel.eta, bits.size)

    dark = ChannelModel(detector_efficiency=0.0, dark_count_prob=0.05)
    bits, a, b, tx, _ = run(channel=dark)
    expected = 1 - (1 - 0.05) ** 2
    assert close(float(np.mean(tx.bob.detected)), expected, bits.size)
    qber, n = sifted_qber(bits, a, b, tx)
    assert close(qber, 0.5, n)  # dark counts carry no information


def test_circuit_shows_alice_eve_channel_bob():
    link = PrepareMeasureLink(ChannelModel(depolarizing=0.1), InterceptResend())
    code = int(encode(np.array(1), np.array(1), np.array(0), np.array(2)))
    qc = link.circuit(code)
    assert [r.name for r in qc.cregs] == ["bob", "eve"]
    ops = qc.count_ops()
    assert ops["measure"] == 2 and ops["barrier"] == 3


def test_batched_execution_matches_one_qubit_per_signal_circuit():
    """The batching shortcut and a literal wide circuit give the same statistics."""
    n = 600
    rng = np.random.default_rng(5)
    bits = rng.integers(0, 2, n)
    a = rng.integers(0, 2, n)
    b = rng.integers(0, 2, n)
    eve = rng.integers(0, 2, n)

    q, cb, ce = (
        QuantumRegister(n, "photon"),
        ClassicalRegister(n, "bob"),
        ClassicalRegister(n, "eve"),
    )
    wide = QuantumCircuit(q, cb, ce)
    for i in range(n):
        prepare(wide, i, int(bits[i]), Basis(int(a[i])))
        measure_in(wide, i, Basis(int(eve[i])), ce[i])
        if eve[i]:
            wide.h(i)  # re-prepare in X after the measurement
        measure_in(wide, i, Basis(int(b[i])), cb[i])
    counts = (
        AerSimulator(method="stabilizer").run(wide, shots=1, seed_simulator=3).result().get_counts()
    )
    bob_bits = np.array([int(c) for c in next(iter(counts)).split()[1][::-1]])  # "eve bob"

    attack = InterceptResend(fraction=1.0)
    attack.plan = lambda n_, rng_: (eve + 1).astype(np.int64)  # same Eve bases as the wide circuit
    link = PrepareMeasureLink(ChannelModel(), attack, seed=3)
    tx = link.transmit(bits.astype(np.int8), a.astype(np.int8), b.astype(np.int8))

    sift = a == b
    wide_qber = float(np.mean(bob_bits[sift] != bits[sift]))
    batched_qber = float(np.mean(tx.bob.bits[sift] != bits[sift]))
    se = np.sqrt(0.25 * 0.75 / sift.sum())
    assert abs(wide_qber - 0.25) < 5 * se and abs(batched_qber - 0.25) < 5 * se


@pytest.mark.slow
def test_device_noise_profile_runs_and_is_small():
    bits, a, b, tx, _ = run(n=8_000, channel=ChannelModel(device="FakeTorino"))
    qber, n = sifted_qber(bits, a, b, tx)
    assert 0.0 < qber < 0.1 and n > 3_000
