import os

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qkd.crypto.otp import xor_bytes
from qkd.crypto.wc_mac import KEY_BYTES, forgery_bound, hashed_blocks, wc_tag, wc_verify


def _aes_block(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


@pytest.mark.parametrize("trial", range(10))
def test_tag_equals_gcm_tag_for_aes_derived_keys(trial):
    aes_key, nonce = os.urandom(32), os.urandom(12)
    aad, plaintext = os.urandom(trial * 5), os.urandom(trial * 11 + 3)
    sealed = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    ciphertext, gcm_tag = sealed[:-16], sealed[-16:]
    wc_key = _aes_block(aes_key, bytes(16)) + _aes_block(aes_key, nonce + b"\x00\x00\x00\x01")
    assert wc_tag(wc_key, aad, ciphertext) == gcm_tag


def test_verify_accepts_genuine_and_rejects_tampering():
    key = os.urandom(KEY_BYTES)
    aad, message = b"alice->bob seq=7", b"meet at the polarizer"
    tag = wc_tag(key, aad, message)
    assert wc_verify(key, aad, message, tag)
    flipped = bytes([message[0] ^ 1]) + message[1:]
    assert not wc_verify(key, aad, flipped, tag)
    assert not wc_verify(key, b"alice->bob seq=8", message, tag)
    assert not wc_verify(key, aad, message, bytes(16))


def test_rejects_wrong_key_size():
    with pytest.raises(ValueError):
        wc_tag(bytes(16), b"", b"")


def test_forgery_bound_counts_blocks():
    assert hashed_blocks(0, 0) == 1
    assert hashed_blocks(16, 17) == 1 + 2 + 1
    assert forgery_bound(16, 17) == 4 / 2**128


def test_otp_roundtrip_and_length_check():
    message = "क्वांटम संदेश".encode()
    pad = os.urandom(len(message))
    ciphertext = xor_bytes(message, pad)
    assert ciphertext != message
    assert xor_bytes(ciphertext, pad) == message
    assert xor_bytes(b"", b"") == b""
    with pytest.raises(ValueError):
        xor_bytes(b"abc", b"ab")
