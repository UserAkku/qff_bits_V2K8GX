"""GF(2^128)/GHASH checks against the AES-GCM spec and against pyca/cryptography."""

import os

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qkd.crypto.gf128 import block_to_int, gf128_mul, ghash, int_to_block


def _aes_block(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _gcm_tag(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Recompute a GCM tag from GHASH: T = E_K(J0) xor GHASH_H(A, C), H = E_K(0^128)."""
    h = block_to_int(_aes_block(key, bytes(16)))
    j0 = nonce + b"\x00\x00\x00\x01"
    mask = block_to_int(_aes_block(key, j0))
    return int_to_block(ghash(h, aad, ciphertext) ^ mask)


def test_gcm_spec_test_case_2():
    # McGrew & Viega, "The Galois/Counter Mode of Operation", Test Case 2.
    key = bytes(16)
    nonce = bytes(12)
    ciphertext = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
    assert _gcm_tag(key, nonce, b"", ciphertext).hex() == "ab6e47d42cec13bdf53a67b21257bddf"


def test_gcm_spec_ghash_value_test_case_2():
    h = block_to_int(bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e"))
    ciphertext = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
    assert int_to_block(ghash(h, b"", ciphertext)).hex() == "f38cbb1ad69223dcc3457ae5b6b0f885"


@pytest.mark.parametrize("trial", range(25))
def test_ghash_matches_pyca_gcm_tags(trial):
    key = os.urandom(32)
    nonce = os.urandom(12)
    aad = os.urandom(trial * 3)
    plaintext = os.urandom(trial * 7 + 1)
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    assert _gcm_tag(key, nonce, aad, ciphertext) == tag


def test_field_axioms_on_random_elements():
    one = 1 << 127  # the multiplicative identity in the reflected representation
    for _ in range(20):
        a, b, c = (block_to_int(os.urandom(16)) for _ in range(3))
        assert gf128_mul(a, one) == a
        assert gf128_mul(a, b) == gf128_mul(b, a)
        assert gf128_mul(a, b ^ c) == gf128_mul(a, b) ^ gf128_mul(a, c)
        assert gf128_mul(gf128_mul(a, b), c) == gf128_mul(a, gf128_mul(b, c))
