import numpy as np
import pytest

from qkd.quantum.attacks import InterceptResend
from qkd.quantum.channel import ChannelModel
from qkd.quantum.entangled import KEY_SETTINGS, EntangledLink, chsh, decode, encode


def run(n=45_000, channel=None, attack=None, seed=3):
    rng = np.random.default_rng(seed)
    a = rng.integers(0, 3, n).astype(np.int8)
    b = rng.integers(0, 3, n).astype(np.int8)
    tx = EntangledLink(channel or ChannelModel(), attack, seed=seed).transmit(a, b)
    valid = tx.alice.detected & tx.bob.detected
    return a, b, tx, valid


def key_qber(a, b, tx, valid):
    key = np.zeros_like(valid)
    for sa, sb in KEY_SETTINGS:
        key |= (a == sa) & (b == sb)
    key &= valid
    return float(np.mean(tx.alice.bits[key] != tx.bob.bits[key])), int(key.sum())


def test_codes_roundtrip():
    for x in range(3):
        for y in range(3):
            for action in range(5):
                assert decode(int(encode(np.array(x), np.array(y), np.array(action)))) == (
                    x,
                    y,
                    action,
                )


def test_ideal_source_violates_chsh_maximally_and_gives_perfect_key():
    a, b, tx, valid = run()
    s, correlators = chsh(a, b, tx.alice.bits, tx.bob.bits, valid)
    assert s == pytest.approx(2 * np.sqrt(2), abs=0.08)
    assert set(correlators) == {"E(a0,b0)", "E(a0,b2)", "E(a2,b0)", "E(a2,b2)"}
    qber, n = key_qber(a, b, tx, valid)
    assert qber == 0.0 and n > 8_000


def test_depolarizing_noise_scales_s_by_visibility():
    p = 0.2  # each arm: visibility (1 - p) per photon, so S = 2 sqrt(2) (1 - p)^2
    a, b, tx, valid = run(channel=ChannelModel(depolarizing=p))
    s, _ = chsh(a, b, tx.alice.bits, tx.bob.bits, valid)
    assert s == pytest.approx(2 * np.sqrt(2) * (1 - p) ** 2, abs=0.08)


def test_intercept_resend_destroys_the_bell_violation():
    a, b, tx, valid = run(attack=InterceptResend(fraction=1.0))
    s, _ = chsh(a, b, tx.alice.bits, tx.bob.bits, valid)
    assert abs(s) <= 2.0  # measured-and-resent photons are no longer entangled
    assert s == pytest.approx(np.sqrt(2), abs=0.1)
    qber, _ = key_qber(a, b, tx, valid)
    assert qber == pytest.approx(0.25, abs=0.02)


def test_loss_is_applied_per_arm():
    channel = ChannelModel(length_km=40, detector_efficiency=0.5)
    _, _, tx, valid = run(channel=channel)
    arm_eta = 10 ** (-0.2 * 20 / 10) * 0.5
    assert float(np.mean(tx.alice.detected)) == pytest.approx(arm_eta, abs=0.01)
    assert float(np.mean(valid)) == pytest.approx(arm_eta**2, abs=0.01)
