import base64
import os

import pytest

from server.kme import BLOCK_BYTES, KME, KMEError, deposit_session_key, link_kmes


def make_pair(session_bytes=4096):
    alice = KME("kme-alice", "sae-alice")
    bob = KME("kme-bob", "sae-bob")
    link_kmes(alice, bob)
    key = os.urandom(session_bytes)
    deposit_session_key(alice, bob, 1, key)
    return alice, bob, key


def raw(entry):
    return base64.b64decode(entry["key"])


def test_status_matches_standard_fields_and_counts_keys():
    alice, bob, _ = make_pair(4096)
    status = alice.get_status("sae-bob")
    assert set(status) == {
        "source_KME_ID",
        "target_KME_ID",
        "master_SAE_ID",
        "slave_SAE_ID",
        "key_size",
        "stored_key_count",
        "max_key_count",
        "max_key_per_request",
        "max_key_size",
        "min_key_size",
        "max_SAE_ID_count",
    }
    assert status["source_KME_ID"] == "kme-alice" and status["target_KME_ID"] == "kme-bob"
    assert status["stored_key_count"] == (2048 * 8) // 256  # half of the session key per direction
    assert bob.get_status("sae-alice")["master_SAE_ID"] == "sae-bob"


def test_master_and_slave_obtain_identical_key_and_it_is_consumed_once():
    alice, bob, _ = make_pair()
    issued = alice.get_key("sae-bob", number=3, size=256)["keys"]
    assert len(issued) == 3 and all(len(raw(k)) == 32 for k in issued)
    ids = [k["key_ID"] for k in issued]
    delivered = bob.get_key_with_ids("sae-alice", ids, caller_sae_id="sae-bob")["keys"]
    assert [raw(k) for k in delivered] == [raw(k) for k in issued]
    with pytest.raises(KMEError) as again:  # no re-fetch
        bob.get_key_with_ids("sae-alice", ids[:1], caller_sae_id="sae-bob")
    assert again.value.status == 400 and "not found" in again.value.message


def test_directions_use_disjoint_key_streams():
    alice, bob, _ = make_pair()
    a_keys = [raw(k) for k in alice.get_key("sae-bob", number=20, size=256)["keys"]]
    b_keys = [raw(k) for k in bob.get_key("sae-alice", number=20, size=256)["keys"]]
    assert not set(a_keys) & set(b_keys)
    assert len(set(a_keys + b_keys)) == 40


def test_odd_sizes_round_up_consumption_to_blocks_and_truncate():
    alice, bob, _ = make_pair()
    before = alice.stored_bits("out")
    key = alice.get_key("sae-bob", number=1, size=136)["keys"][0]  # 17 bytes -> 2 blocks
    assert len(raw(key)) == 17
    assert before - alice.stored_bits("out") == 2 * BLOCK_BYTES * 8
    assert len(raw(bob.get_key_with_ids("sae-alice", [key["key_ID"]], "sae-bob")["keys"][0])) == 17


def test_wrong_slave_and_wrong_caller_are_rejected():
    alice, bob, _ = make_pair()
    key_id = alice.get_key("sae-bob")["keys"][0]["key_ID"]
    with pytest.raises(KMEError) as who:
        bob.get_key_with_ids("sae-alice", [key_id], caller_sae_id="sae-mallory")
    assert who.value.status == 401
    with pytest.raises(KMEError) as who:
        bob.get_key_with_ids("sae-mallory", [key_id], caller_sae_id="sae-bob")
    assert who.value.status == 400
    with pytest.raises(KMEError):
        alice.get_key("sae-mallory")
    # the master cannot read its own issued key back: that is the slave's job
    with pytest.raises(KMEError):
        alice.get_key_with_ids("sae-bob", [key_id], caller_sae_id="sae-alice")


def test_request_validation_and_insufficient_key():
    alice, bob, _ = make_pair(512)
    for kwargs, status in [
        ({"size": 100}, 400),
        ({"size": 64}, 400),
        ({"size": 1 << 20}, 400),
        ({"number": 0}, 400),
        ({"number": 1000}, 400),
        ({"extension_mandatory": [{"route": "direct"}]}, 400),
        ({"additional_slave_SAE_IDs": ["sae-carol"]}, 400),
    ]:
        with pytest.raises(KMEError) as err:
            alice.get_key("sae-bob", **kwargs)
        assert err.value.status == status, kwargs
    alice.get_key("sae-bob", number=4, size=512)  # 256 bytes per direction in total = 4 x 64 B
    with pytest.raises(KMEError) as err:
        alice.get_key("sae-bob", number=1, size=256)
    assert err.value.status == 503
    assert "needed_bits" in err.value.body()["details"][0]


def test_idempotent_retry_does_not_burn_a_second_batch():
    alice, bob, _ = make_pair()
    ext = [{"idempotency_key": "req-1"}]
    first = alice.get_key("sae-bob", number=2, extension_optional=ext)
    left = alice.stored_bits("out")
    again = alice.get_key("sae-bob", number=2, extension_optional=ext)
    assert again == first and alice.stored_bits("out") == left
    other = alice.get_key("sae-bob", number=2, extension_optional=[{"idempotency_key": "req-2"}])
    assert other != first


def test_master_copy_is_zeroed_after_issue_and_slave_copy_after_delivery():
    alice, bob, _ = make_pair()
    issued = alice.get_key("sae-bob", number=1, size=256)["keys"][0]
    reservation = bob._reserved[issued["key_ID"]]
    held = reservation.blocks
    assert b"".join(held)[:32] == raw(issued)
    bob.get_key_with_ids("sae-alice", [issued["key_ID"]], "sae-bob")
    assert all(not any(block) for block in held)


def test_ledger_and_counters_track_flows_without_key_material():
    alice, bob, _ = make_pair()
    key = alice.get_key("sae-bob", number=1, size=256)["keys"][0]
    bob.get_key_with_ids("sae-alice", [key["key_ID"]], "sae-bob")
    assert [e.kind for e in alice.ledger] == ["deposit", "deposit", "issue"]
    assert [e.kind for e in bob.ledger][-1] == "deliver"
    assert alice.counters["issued_bits"] == bob.counters["delivered_bits"] == 256
    snap = alice.snapshot()
    assert all(isinstance(v, int | str) for v in snap.values())  # counts and ids only
    assert snap["incoming_bits"] > 0


def test_deposit_ids_are_deterministic_so_both_kmes_agree():
    a1, b1, key = make_pair()
    a2, b2 = KME("kme-alice", "sae-alice"), KME("kme-bob", "sae-bob")
    link_kmes(a2, b2)
    deposit_session_key(a2, b2, 1, key)
    assert list(a1._master_pool) == list(a2._master_pool) == list(b1._slave_pool)
