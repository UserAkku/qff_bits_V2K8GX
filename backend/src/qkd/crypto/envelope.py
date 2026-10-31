"""Message envelopes: how a chat message is protected with QKD key (spec version QKDMSG/1).

Two modes, both bound to a header that names sender, recipient, direction
counter and key IDs:

``otp-wc``  (information-theoretic *given* a perfect key)
    padded plaintext XOR pad, then a Wegman-Carter tag
    ``GHASH_H(header, ciphertext) xor P``. One QKD key of ``bucket + 32``
    bytes is consumed: ``pad || H || P``. Nothing computational is involved;
    its guarantees are exactly as strong as the key.

``aes-gcm`` (computational)
    one fresh 256-bit QKD key per message, domain-separated with
    HKDF-SHA256 over the header, AES-256-GCM with a random 96-bit nonce.
    Cheap on key (32 bytes per message) at the price of relying on AES.

Plaintexts are length-prefixed and zero-padded to a bucket size so ciphertext
length reveals only the bucket. Keys are single-use by construction (the KME
deletes a key once delivered), so a replayed envelope fails at key retrieval
and a tampered one fails authentication.

The same byte layouts are implemented in TypeScript (frontend/src/crypto);
``shared/test-vectors/envelope.json`` pins them.
"""

from __future__ import annotations

import base64
import hmac
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from qkd.crypto.otp import xor_bytes
from qkd.crypto.wc_mac import KEY_BYTES as MAC_KEY_BYTES
from qkd.crypto.wc_mac import wc_tag

VERSION = "QKDMSG/1"
BUCKETS = (64, 128, 256, 512, 1024)
MAX_PLAINTEXT = BUCKETS[-1] - 2
AES_KEY_BYTES = 32
NONCE_BYTES = 12
MODES = ("otp-wc", "aes-gcm")


class AuthenticationError(Exception):
    """The envelope was modified, or was built with a different key."""


def bucket_for(length: int) -> int:
    if length > MAX_PLAINTEXT:
        raise ValueError(f"messages longer than {MAX_PLAINTEXT} bytes must be split")
    return next(b for b in BUCKETS if length + 2 <= b)


def key_bytes_needed(mode: str, plaintext_len: int) -> int:
    """Bytes of QKD key one message of this length consumes."""
    if mode == "otp-wc":
        return bucket_for(plaintext_len) + MAC_KEY_BYTES
    if mode == "aes-gcm":
        return AES_KEY_BYTES
    raise ValueError(f"unknown mode {mode!r}")


def pad(plaintext: bytes) -> bytes:
    bucket = bucket_for(len(plaintext))
    return len(plaintext).to_bytes(2, "big") + plaintext + bytes(bucket - 2 - len(plaintext))


def unpad(padded: bytes) -> bytes:
    length = int.from_bytes(padded[:2], "big")
    if length > len(padded) - 2 or any(padded[2 + length :]):
        raise AuthenticationError("malformed padding")
    return padded[2 : 2 + length]


def header(
    mode: str, sender: str, recipient: str, seq: int, key_ids: list[str], bucket: int
) -> bytes:
    """Canonical authenticated header (the AAD)."""
    return "|".join(
        [VERSION, mode, sender, recipient, str(seq), ",".join(key_ids), str(bucket)]
    ).encode()


@dataclass(frozen=True)
class Sealed:
    mode: str
    sender: str
    recipient: str
    seq: int
    key_ids: list[str]
    bucket: int
    ciphertext: bytes
    tag: bytes | None = None  # otp-wc
    nonce: bytes | None = None  # aes-gcm

    def to_json(self, message_id: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": message_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "mode": self.mode,
            "seq": self.seq,
            "key_ids": self.key_ids,
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "aad": self.header_text,
        }
        if self.tag is not None:
            out["tag"] = self.tag.hex()
        if self.nonce is not None:
            out["nonce"] = self.nonce.hex()
        return out

    @property
    def header_text(self) -> str:
        return header(
            self.mode, self.sender, self.recipient, self.seq, self.key_ids, self.bucket
        ).decode()

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Sealed:
        ciphertext = base64.b64decode(data["ciphertext"])
        # The bucket is recomputed from what we can see; the header (AAD) binds it cryptographically.
        bucket = len(ciphertext) if data["mode"] == "otp-wc" else len(ciphertext) - 16
        return cls(
            mode=data["mode"],
            sender=data["sender"],
            recipient=data["recipient"],
            seq=int(data["seq"]),
            key_ids=list(data["key_ids"]),
            bucket=bucket,
            ciphertext=ciphertext,
            tag=bytes.fromhex(data["tag"]) if data.get("tag") else None,
            nonce=bytes.fromhex(data["nonce"]) if data.get("nonce") else None,
        )


def seal(
    mode: str,
    sender: str,
    recipient: str,
    seq: int,
    plaintext: bytes,
    key: bytes,
    key_ids: list[str],
    nonce: bytes | None = None,
) -> Sealed:
    if len(key) != key_bytes_needed(mode, len(plaintext)):
        raise ValueError(
            f"{mode} needs {key_bytes_needed(mode, len(plaintext))} key bytes, got {len(key)}"
        )
    padded = pad(plaintext)
    bucket = len(padded)
    aad = header(mode, sender, recipient, seq, key_ids, bucket)
    if mode == "otp-wc":
        ciphertext = xor_bytes(padded, key[:bucket])
        tag = wc_tag(key[bucket:], aad, ciphertext)
        return Sealed(mode, sender, recipient, seq, key_ids, bucket, ciphertext, tag=tag)
    nonce = nonce if nonce is not None else os.urandom(NONCE_BYTES)
    sealed = AESGCM(_aead_key(key, aad)).encrypt(nonce, padded, aad)
    return Sealed(mode, sender, recipient, seq, key_ids, bucket, sealed, nonce=nonce)


def open_sealed(sealed: Sealed, key: bytes) -> bytes:
    aad = header(
        sealed.mode, sealed.sender, sealed.recipient, sealed.seq, sealed.key_ids, sealed.bucket
    )
    if sealed.mode == "otp-wc":
        if len(key) != sealed.bucket + MAC_KEY_BYTES or sealed.tag is None:
            raise AuthenticationError("wrong key length or missing tag")
        expected = wc_tag(key[sealed.bucket :], aad, sealed.ciphertext)
        if not hmac.compare_digest(expected, sealed.tag):
            raise AuthenticationError(
                "authentication tag mismatch: message was modified or the key differs"
            )
        return unpad(xor_bytes(sealed.ciphertext, key[: sealed.bucket]))
    if sealed.nonce is None or len(key) != AES_KEY_BYTES:
        raise AuthenticationError("wrong key length or missing nonce")
    try:
        padded = AESGCM(_aead_key(key, aad)).decrypt(sealed.nonce, sealed.ciphertext, aad)
    except InvalidTag as exc:
        raise AuthenticationError(
            "authentication tag mismatch: message was modified or the key differs"
        ) from exc
    return unpad(padded)


def _aead_key(key: bytes, aad: bytes) -> bytes:
    """Domain-separate the QKD key per message header (HKDF-SHA256)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=None,
        info=VERSION.encode() + b"|aes-gcm|" + aad,
    ).derive(key)
