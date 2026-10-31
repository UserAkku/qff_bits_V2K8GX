import asyncio
import os
from dataclasses import replace

import numpy as np
import pytest

from qkd.auth.keypool import AuthKeyExhausted, AuthKeyPool
from qkd.auth.transcript import TranscriptAuthenticator, session_auth_bytes
from qkd.classical.channel import (
    ClassicalChannel,
    Message,
    ProtocolAbort,
    pack_bits,
    pack_symbols,
    unpack_bits,
    unpack_symbols,
)
from qkd.crypto.gf128 import PolyHash, block_to_int, ghash, int_to_block


def msg(seq, sender="alice", kind="x", **payload):
    return Message(seq, sender, kind, payload)


def pair():
    key = os.urandom(session_auth_bytes())
    return TranscriptAuthenticator(key), TranscriptAuthenticator(key)


def test_polyhash_matches_ghash_for_any_chunking():
    h = block_to_int(os.urandom(16))
    data = os.urandom(100)
    ph = PolyHash(h)
    for start in range(0, 100, 7):
        ph.update(data[start : start + 7])
    final = (0 << 64) | (len(data) * 8)
    assert int_to_block(ph.digest(final)) == int_to_block(ghash(h, b"", data))


def test_matching_transcripts_verify_both_directions_at_each_checkpoint():
    alice, bob = pair()
    for m in (msg(0, kind="a", v=1), msg(1, "bob", "b", v=[1, 2]), msg(2, kind="c")):
        alice.absorb(m)
        bob.absorb(m)
    for checkpoint in range(2):
        assert bob.verify(checkpoint, "alice", alice.tag(checkpoint, "alice"))
        assert alice.verify(checkpoint, "bob", bob.tag(checkpoint, "bob"))


def test_any_modification_reorder_or_drop_is_detected():
    original = [msg(0, kind="a", v=1), msg(1, "bob", "b", v=2), msg(2, kind="c", v=3)]
    variants = {
        "modified": [original[0], replace(original[1], payload={"v": 9}), original[2]],
        "reordered": [original[1], original[0], original[2]],
        "dropped": original[:2],
        "injected": [*original, msg(3, kind="d")],
    }
    for name, seen_by_bob in variants.items():
        alice, bob = pair_with_same_key()
        for m in original:
            alice.absorb(m)
        for m in seen_by_bob:
            bob.absorb(m)
        assert not bob.verify(0, "alice", alice.tag(0, "alice")), name


def pair_with_same_key():
    return pair()


def test_tags_differ_by_checkpoint_and_role_and_pad_is_per_tag():
    alice, _ = pair()
    alice.absorb(msg(0))
    tags = {alice.tag(c, r) for c in range(2) for r in ("alice", "bob")}
    assert len(tags) == 4


def test_wrong_key_length_and_checkpoint():
    with pytest.raises(ValueError):
        TranscriptAuthenticator(b"short")
    alice, _ = pair()
    with pytest.raises(ValueError):
        alice.tag(5, "alice")


def test_forgery_bound_is_tiny():
    alice, _ = pair()
    alice.absorb(msg(0, blob="x" * 10_000))
    assert alice.forgery_bound < 1e-33


def test_keypool_takes_in_order_and_runs_out():
    pool = AuthKeyPool.from_preshared(bytes(range(20)))
    assert pool.take(5) == bytes(range(5))
    assert pool.take(5) == bytes(range(5, 10))
    assert pool.available == 10 and pool.consumed == 10
    pool.replenish(b"\xff" * 4)
    assert pool.available == 14 and pool.replenished == 4
    with pytest.raises(AuthKeyExhausted):
        pool.take(15)


def test_bit_and_symbol_packing_roundtrip():
    rng = np.random.default_rng(0)
    for n in (0, 1, 7, 8, 9, 1000):
        bits = rng.integers(0, 2, n, dtype=np.uint8)
        assert np.array_equal(unpack_bits(pack_bits(bits)), bits)
        symbols = rng.integers(0, 3, n, dtype=np.uint8)
        assert np.array_equal(unpack_symbols(pack_symbols(symbols)), symbols)


def test_channel_delivers_taps_tampering_and_aborts():
    async def scenario():
        seen = []
        channel = ClassicalChannel(taps=[seen.append], timeout_s=0.2)
        await channel.send("alice", "hello", {"v": 1})
        got = await channel.receive("bob", "hello")
        assert got.payload == {"v": 1} and len(seen) == 1 and channel.messages_sent == 1

        channel.tamper = lambda m: replace(m, payload={"v": 666})
        await channel.send("bob", "reply", {"v": 2})
        assert (await channel.receive("alice", "reply")).payload == {"v": 666}

        with pytest.raises(ProtocolAbort):  # nothing to receive -> timeout
            await channel.receive("bob", "never")

        channel.tamper = None
        await channel.send("alice", "oops", {})
        with pytest.raises(ProtocolAbort):  # unexpected kind
            await channel.receive("bob", "expected")

        await channel.send("alice", "abort", {"reason": "QBER too high", "stage": "estimate"})
        with pytest.raises(ProtocolAbort) as info:
            await channel.receive("bob", "anything")
        assert info.value.reason == "QBER too high" and info.value.stage == "estimate"

    asyncio.run(scenario())
