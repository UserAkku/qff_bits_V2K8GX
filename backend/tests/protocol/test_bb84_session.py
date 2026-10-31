"""End-to-end BB84 sessions: real Qiskit circuits, Cascade, finite-key privacy amplification, auth."""

import os
from dataclasses import replace

import numpy as np
import pytest

from qkd.auth.keypool import AuthKeyPool
from qkd.classical.channel import Message
from qkd.protocol.bb84 import run_bb84
from qkd.protocol.finite_key import h2, mu
from qkd.protocol.params import SessionParams
from qkd.quantum.attacks import EveBasis, InterceptResend
from qkd.quantum.channel import ChannelModel
from qkd.quantum.prepare_measure import PrepareMeasureLink
from qkd.randomness import Randomness

PARAMS = SessionParams(n_key=8_192, k_test=4_096, chunk=20_000)


def pools(n_bytes=2_000):
    secret = os.urandom(n_bytes)
    return AuthKeyPool.from_preshared(secret), AuthKeyPool.from_preshared(secret)


async def session(channel=None, attack=None, params=PARAMS, seed=11, **kwargs):
    alice, bob = pools()
    link = PrepareMeasureLink(channel or ChannelModel(), attack, seed=seed)
    result = await run_bb84(params, link, alice, bob, seed=seed, **kwargs)
    return result, alice, bob


async def test_clean_channel_delivers_a_key_and_keeps_authentication_pool_whole():
    result, alice, bob = await session()
    assert result.ok and result.abort is None
    assert result.stats["qber"] == 0.0 and result.stats["key_error_rate"] == 0.0
    breakdown = result.stats["key_length"]
    expected_bits = (breakdown["length"] - PARAMS.auth_refill_bits) // 8 * 8
    assert result.key_bits == expected_bits > 1_000
    assert len(result.key) * 8 == result.key_bits
    # burn 80 bytes at the start, pay 80 bytes back from the fresh key
    assert alice.available == bob.available == 2_000
    assert alice.material == bob.material
    assert result.ground_truth["eve_info_bits"] == 0.0
    assert (
        result.stats["sifted_key"] >= PARAMS.n_key and result.stats["sifted_test"] >= PARAMS.k_test
    )


async def test_noise_costs_key_and_matches_channel_model():
    channel = ChannelModel(depolarizing=0.04)  # QBER 2%
    result, *_ = await session(channel)
    assert result.ok
    assert result.stats["qber"] == pytest.approx(0.02, abs=0.006)
    assert result.stats["key_error_rate"] == pytest.approx(0.02, abs=0.005)
    clean, *_ = await session()
    assert result.key_bits < clean.key_bits
    assert 1.0 < result.stats["reconciliation_efficiency"] < 1.4


async def test_full_intercept_resend_is_detected_and_aborts_before_any_leak():
    result, alice, bob = await session(attack=InterceptResend(fraction=1.0))
    assert not result.ok and result.key is None
    assert result.abort["stage"] == "estimation"
    assert result.abort["detail"]["qber"] == pytest.approx(0.25, abs=0.03)
    # a failed session still burns its authentication key (both sides in lock-step)
    assert alice.available == bob.available == 2_000 - PARAMS.auth_key_bytes


async def test_partial_eve_is_tolerated_but_costs_key_and_eve_info_stays_below_bound():
    attack = InterceptResend(fraction=0.12)  # Z-sample error 3%
    result, *_ = await session(attack=attack)
    clean, *_ = await session()
    assert result.ok
    assert result.stats["qber"] == pytest.approx(0.03, abs=0.007)
    assert result.key_bits < clean.key_bits
    truth = result.ground_truth
    assert truth["eve_attempted"] > 0 and truth["eve_guess_accuracy"] == 1.0
    # Eve's true information about the raw key is far below the entropy the finite-key
    # bound assumed she could have, n * h(Q_tol + mu) (the bound is sound and conservative).
    bound = PARAMS.n_key * h2(PARAMS.q_tol + mu(PARAMS.n_key, PARAMS.k_test, 1e-10 / 4))
    assert truth["eve_info_bits"] < bound
    # the secure length leaves at least as many bits of uncertainty as Eve's real knowledge
    assert result.stats["key_length"]["length"] + truth["eve_info_bits"] < PARAMS.n_key


async def test_fixed_z_basis_eve_passes_the_z_test_but_cannot_corrupt_silently():
    """Measuring in Z hides from a Z-basis test, yet destroys the X-basis key: reconciliation fails."""
    result, *_ = await session(attack=InterceptResend(basis=EveBasis.Z))
    assert not result.ok
    assert result.abort["stage"] in {"reconciliation", "verification"}


async def test_tampering_with_a_public_message_is_caught_by_the_transcript_mac():
    def bump_error_count(message: Message) -> Message:
        if message.kind == "estimate":
            payload = dict(message.payload)
            payload["errors"] = int(payload["errors"]) + 1
            return replace(message, payload=payload)
        return message

    result, *_ = await session(tamper=bump_error_count)
    assert not result.ok
    assert result.abort["stage"] == "authentication"
    assert "transcript" in result.abort["reason"]


async def test_tampering_with_the_final_amplification_message_aborts():
    def shorten_key(message: Message) -> Message:
        if message.kind == "amplify":
            payload = dict(message.payload)
            payload["length"] = int(payload["length"]) - 1
            return replace(message, payload=payload)
        return message

    result, *_ = await session(tamper=shorten_key)
    assert not result.ok and result.abort["stage"] in {"amplification", "authentication"}


async def test_garbage_from_an_active_attacker_aborts_cleanly():
    def garble(message: Message) -> Message:
        if message.kind == "select":
            return replace(message, payload={"key": "zz", "test": "zz"})
        return message

    result, *_ = await session(tamper=garble)
    assert not result.ok and result.abort["stage"] == "protocol"


async def test_exhausted_authentication_key_blocks_the_session():
    alice, bob = (
        AuthKeyPool.from_preshared(os.urandom(20)),
        AuthKeyPool.from_preshared(os.urandom(20)),
    )
    link = PrepareMeasureLink(ChannelModel(), None, seed=1)
    result = await run_bb84(PARAMS, link, alice, bob, seed=1)
    assert not result.ok and result.abort["stage"] == "authentication"
    assert "pre-shared" in result.abort["reason"]


async def test_too_lossy_link_gives_up_at_the_signal_budget():
    channel = ChannelModel(length_km=200)  # 40 dB loss: 1e-4 of photons arrive
    params = replace(PARAMS, max_signals=60_000)
    result, *_ = await session(channel, params=params)
    assert not result.ok and result.abort["stage"] == "quantum"


async def test_blocks_too_small_for_the_security_parameters_yield_no_key():
    params = SessionParams(n_key=512, k_test=512, chunk=5_000)
    result, *_ = await session(params=params)
    assert not result.ok and result.abort["stage"] == "amplification"


async def test_seeded_sessions_are_reproducible():
    a, *_ = await session(ChannelModel(depolarizing=0.03), seed=21)
    b, *_ = await session(ChannelModel(depolarizing=0.03), seed=21)
    assert a.ok and b.ok and a.key == b.key
    assert a.stats["leak_ec"] == b.stats["leak_ec"]


async def test_events_cover_every_stage_in_order():
    result, *_ = await session()
    stages = [e.stage for e in result.events]
    order = [
        "quantum",
        "sifting",
        "estimation",
        "reconciliation",
        "verification",
        "authentication",
        "amplification",
        "result",
    ]
    first = [stages.index(s) for s in order]
    assert first == sorted(first)
    alice_prepared = next(e for e in result.events if e.kind == "alice_prepared")
    assert len(alice_prepared.data["bits"]) == PARAMS.preview_signals


def test_independent_random_streams_for_the_same_seed():
    a, b = Randomness(5, 0), Randomness(5, 1)
    assert not np.array_equal(a.bits(256), b.bits(256))
    assert np.array_equal(Randomness(5, 1).bits(64), Randomness(5, 1).bits(64))
