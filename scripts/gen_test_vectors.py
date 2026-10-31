"""Generate shared/test-vectors/envelope.json (deterministic) for the Python and TypeScript suites.

Run from the repository root:  cd backend && uv run python ../scripts/gen_test_vectors.py
"""

import base64
import json
from pathlib import Path

from qkd.crypto.envelope import key_bytes_needed, seal
from qkd.crypto.gf128 import block_to_int, gf128_mul, ghash, int_to_block

OUT = Path(__file__).resolve().parents[1] / "shared" / "test-vectors" / "envelope.json"
KEY_ID = "550e8400-e29b-41d4-a716-446655440000"


def stream(label: str, n: int) -> bytes:
    """Deterministic pseudo-key for vectors only (never used for real keys)."""
    import hashlib

    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}:{counter}".encode()).digest()
        counter += 1
    return out[:n]


CASES = [
    ("otp-wc", "alice", "bob", 0, "hello"),
    ("otp-wc", "bob", "alice", 41, "नमस्ते quantum 🔐"),
    ("otp-wc", "alice", "bob", 7, ""),
    ("otp-wc", "alice", "bob", 9, "x" * 300),
    ("aes-gcm", "alice", "bob", 1, "hello"),
    ("aes-gcm", "bob", "alice", 2, "गुप्त संदेश"),
    ("aes-gcm", "alice", "bob", 3, "y" * 700),
]


def main() -> None:
    envelopes = []
    for i, (mode, sender, recipient, seq, text) in enumerate(CASES):
        plaintext = text.encode()
        key = stream(f"envelope-key-{i}", key_bytes_needed(mode, len(plaintext)))
        nonce = stream(f"envelope-nonce-{i}", 12) if mode == "aes-gcm" else None
        sealed = seal(mode, sender, recipient, seq, plaintext, key, [KEY_ID], nonce)
        data = sealed.to_json("msg-vector")
        envelopes.append(
            {
                "mode": mode,
                "sender": sender,
                "recipient": recipient,
                "seq": seq,
                "key_ids": [KEY_ID],
                "plaintext": base64.b64encode(plaintext).decode(),
                "key": key.hex(),
                "nonce": nonce.hex() if nonce else None,
                "aad": data["aad"],
                "ciphertext": data["ciphertext"],
                "tag": data.get("tag"),
            }
        )
    h = block_to_int(bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e"))
    c = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
    ghash_vectors = [
        {
            "name": "GCM spec test case 2",
            "h": "66e94bd4ef8a2c3b884cfa59ca342b2e",
            "aad": "",
            "ciphertext": c.hex(),
            "ghash": int_to_block(ghash(h, b"", c)).hex(),
        }
    ]
    mul = [
        {
            "a": a.hex(),
            "b": b.hex(),
            "product": int_to_block(gf128_mul(block_to_int(a), block_to_int(b))).hex(),
        }
        for a, b in [
            (stream("mul-a", 16), stream("mul-b", 16)),
            (bytes.fromhex("80" + "00" * 15), stream("mul-c", 16)),
        ]
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps({"envelope": envelopes, "ghash": ghash_vectors, "gf128_mul": mul}, indent=2)
        + "\n"
    )
    print(f"wrote {OUT} ({len(envelopes)} envelope vectors)")


if __name__ == "__main__":
    main()
