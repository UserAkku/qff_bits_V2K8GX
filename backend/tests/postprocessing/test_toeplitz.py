import numpy as np
import pytest

from qkd.postprocessing import toeplitz
from qkd.postprocessing.toeplitz import seed_length, toeplitz_hash, toeplitz_matrix


@pytest.mark.parametrize(("n_in", "n_out"), [(1, 1), (8, 3), (64, 64), (257, 100), (1000, 731)])
def test_fft_hash_matches_dense_matrix(n_in, n_out):
    rng = np.random.default_rng(n_in * 31 + n_out)
    seed = rng.integers(0, 2, seed_length(n_in, n_out), dtype=np.uint8)
    key = rng.integers(0, 2, n_in, dtype=np.uint8)
    dense = toeplitz_matrix(seed, n_in, n_out).astype(np.int64) @ key.astype(np.int64) % 2
    assert np.array_equal(toeplitz_hash(seed, key, n_out), dense.astype(np.uint8))


def test_chunked_path_matches_single_pass(monkeypatch):
    rng = np.random.default_rng(7)
    n_in, n_out = 5000, 1200
    seed = rng.integers(0, 2, seed_length(n_in, n_out), dtype=np.uint8)
    key = rng.integers(0, 2, n_in, dtype=np.uint8)
    whole = toeplitz_hash(seed, key, n_out)
    monkeypatch.setattr(toeplitz, "_FFT_CHUNK", 777)
    assert np.array_equal(toeplitz_hash(seed, key, n_out), whole)


def test_large_key_is_exact():
    rng = np.random.default_rng(1)
    n_in, n_out = 300_000, 150_000
    seed = rng.integers(0, 2, seed_length(n_in, n_out), dtype=np.uint8)
    key = rng.integers(0, 2, n_in, dtype=np.uint8)
    out = toeplitz_hash(seed, key, n_out)
    # Spot-check rows against direct dot products.
    for i in rng.integers(0, n_out, 25):
        row = seed[i - np.arange(n_in) + n_in - 1]
        assert out[i] == int(row.astype(np.int64) @ key.astype(np.int64)) % 2


def test_linearity_over_gf2():
    rng = np.random.default_rng(3)
    n_in, n_out = 512, 200
    seed = rng.integers(0, 2, seed_length(n_in, n_out), dtype=np.uint8)
    a = rng.integers(0, 2, n_in, dtype=np.uint8)
    b = rng.integers(0, 2, n_in, dtype=np.uint8)
    assert np.array_equal(
        toeplitz_hash(seed, a ^ b, n_out),
        toeplitz_hash(seed, a, n_out) ^ toeplitz_hash(seed, b, n_out),
    )


def test_rejects_bad_shapes():
    with pytest.raises(ValueError):
        toeplitz_hash(np.zeros(10, np.uint8), np.zeros(5, np.uint8), 6)
    with pytest.raises(ValueError):
        toeplitz_hash(np.zeros(3, np.uint8), np.zeros(5, np.uint8), 2)
