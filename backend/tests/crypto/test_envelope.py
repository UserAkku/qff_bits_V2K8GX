import base64
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from qkd.crypto.envelope import (
    BUCKETS,
    MAX_PLAINTEXT,
    AuthenticationError,
    Sealed,
    bucket_for,
    key_bytes_needed,
    open_sealed,
    seal,
)

VECTORS = Path(__file__).resolve().parents[3] / "shared" / "test-vectors" / "envelope.json"
KEY_IDS = ["550e8400-e29b-41d4-a716-446655440000"]


def roundtrip(mode, text=b"meet me at the polarizer"):
    key = os.urandom(key_bytes_needed(mode, len(text)))
    sealed = seal(mode, "alice", "bob", 3, text, key, KEY_IDS)
    return sealed, key


@pytest.mark.parametrize("mode", ["otp-wc", "aes-gcm"])
def test_roundtrip_including_unicode_and_empty(mode):
    for text in (b"", "नमस्ते quantum 🔐".encode(), os.urandom(MAX_PLAINTEXT)):
        key = os.urandom(key_bytes_needed(mode, len(text)))
        sealed = seal(mode, "alice", "bob", 0, text, key, KEY_IDS)
        wire = Sealed.from_json(sealed.to_json("msg-00000001"))
        assert open_sealed(wire, key) == text


def test_key_consumption_per_mode():
    assert key_bytes_needed("aes-gcm", 5) == 32 and key_bytes_needed("aes-gcm", 1000) == 32
    assert key_bytes_needed("otp-wc", 5) == 64 + 32
    assert key_bytes_needed("otp-wc", 62) == 64 + 32 and key_bytes_needed("otp-wc", 63) == 128 + 32
    assert key_bytes_needed("otp-wc", MAX_PLAINTEXT) == 1024 + 32
    with pytest.raises(ValueError):
        bucket_for(MAX_PLAINTEXT + 1)


def test_ciphertext_length_reveals_only_the_bucket():
    lengths = set()
    for n in (1, 10, 40, 62):
        sealed, _ = roundtrip("otp-wc", os.urandom(n))
        lengths.add(len(sealed.ciphertext))
    assert lengths == {BUCKETS[0]}


@pytest.mark.parametrize("mode", ["otp-wc", "aes-gcm"])
def test_every_single_bit_flip_in_ciphertext_is_rejected(mode):
    sealed, key = roundtrip(mode)
    for byte in range(len(sealed.ciphertext)):
        flipped = bytearray(sealed.ciphertext)
        flipped[byte] ^= 0x80
        with pytest.raises(AuthenticationError):
            open_sealed(replace(sealed, ciphertext=bytes(flipped)), key)


@pytest.mark.parametrize("mode", ["otp-wc", "aes-gcm"])
def test_header_fields_are_authenticated(mode):
    sealed, key = roundtrip(mode)
    for tampered in (
        replace(sealed, sender="mallory"),
        replace(sealed, recipient="carol"),
        replace(sealed, seq=sealed.seq + 1),
        replace(sealed, key_ids=["00000000-0000-4000-8000-000000000000"]),
    ):
        with pytest.raises(AuthenticationError):
            open_sealed(tampered, key)


@pytest.mark.parametrize("mode", ["otp-wc", "aes-gcm"])
def test_wrong_key_is_rejected(mode):
    sealed, key = roundtrip(mode)
    with pytest.raises(AuthenticationError):
        open_sealed(sealed, os.urandom(len(key)))


def test_tag_flip_rejected_and_wrong_key_length_refused():
    sealed, key = roundtrip("otp-wc")
    with pytest.raises(AuthenticationError):
        open_sealed(replace(sealed, tag=bytes(16)), key)
    with pytest.raises(ValueError):
        seal("otp-wc", "a", "b", 0, b"x", key[:-1], KEY_IDS)
    with pytest.raises(AuthenticationError):
        open_sealed(sealed, key[:-1])


def test_otp_is_malleable_without_the_mac_which_is_why_the_tag_exists():
    """Flipping a ciphertext bit flips the same plaintext bit; only the tag stops it."""
    key = os.urandom(key_bytes_needed("otp-wc", 8))
    sealed = seal("otp-wc", "alice", "bob", 0, b"PAY 0100", key, KEY_IDS)
    forged = bytearray(sealed.ciphertext)
    forged[2 + 4] ^= ord("0") ^ ord(
        "9"
    )  # turn the first digit '0' into '9' without knowing the key
    from qkd.crypto.otp import xor_bytes

    assert xor_bytes(bytes(forged), key[: len(forged)])[2:10] == b"PAY 9100"
    with pytest.raises(AuthenticationError):
        open_sealed(replace(sealed, ciphertext=bytes(forged)), key)


def test_committed_test_vectors_match():
    """Vectors consumed by the TypeScript implementation (regenerate with scripts/gen_test_vectors.py)."""
    vectors = json.loads(VECTORS.read_text())["envelope"]
    assert len(vectors) >= 6
    for v in vectors:
        key = bytes.fromhex(v["key"])
        nonce = bytes.fromhex(v["nonce"]) if v.get("nonce") else None
        sealed = seal(
            v["mode"],
            v["sender"],
            v["recipient"],
            v["seq"],
            base64.b64decode(v["plaintext"]),
            key,
            v["key_ids"],
            nonce,
        )
        assert sealed.to_json("msg-vector")["ciphertext"] == v["ciphertext"]
        assert (sealed.tag.hex() if sealed.tag else None) == v.get("tag")
        assert sealed.header_text == v["aad"]
        assert open_sealed(Sealed.from_json(sealed.to_json("msg-vector")), key) == base64.b64decode(
            v["plaintext"]
        )
