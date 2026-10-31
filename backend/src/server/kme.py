"""Key Management Entities exposing the ETSI GS QKD 014 V1.1.1 key-delivery semantics.

Two KMEs (one per site) hold identical copies of every key block that QKD
produced between them. Keys flow in two *separate* streams, one per direction
(``master -> slave``): the master's KME hands keys out of its outgoing stream
and tells the peer KME which blocks it used, and the slave's KME gives those
exact blocks to the slave SAE when it asks by key ID. Because each direction
has its own stream, a one-time pad is never issued twice, even when both
parties send at the same time.

Rules taken from the standard (and the gaps its critics point out):

* a key is delivered once and then deleted (``enc_keys`` for the master,
  ``dec_keys`` for the slave); blocks are zeroed on deletion;
* the slave can only fetch keys that were issued to it by the named master (401
  otherwise);
* the allocation is registered at the peer *before* the master gets its answer,
  so the slave never races ahead of the key association;
* ``extension_optional: [{"idempotency_key": ...}]`` makes a retried request
  return the same keys instead of burning a second batch.

The KME is inside the trust boundary of its site. In a deployment, SAEs reach
it over mutually-authenticated TLS from the same secure site; this prototype
substitutes a bearer token per SAE (see docs/security-model.md).
"""

from __future__ import annotations

import base64
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from math import ceil
from typing import Any

BLOCK_BYTES = 16
BLOCK_BITS = BLOCK_BYTES * 8
_NAMESPACE = uuid.UUID("6f1d9a50-0b8e-4c43-9a6e-51d1c0de5a11")


class KMEError(Exception):
    """Maps to an ETSI Error object and one of 400 / 401 / 503."""

    def __init__(self, status: int, message: str, details: list[dict[str, str]] | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.details = details

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {"message": self.message}
        if self.details:
            out["details"] = self.details
        return out


def _zero(blocks: list[bytearray]) -> None:
    for block in blocks:
        for i in range(len(block)):
            block[i] = 0


@dataclass
class Reservation:
    """Blocks a master has issued as one key; held by the slave's KME until the slave fetches them."""

    master_sae: str
    slave_sae: str
    size_bits: int
    blocks: list[bytearray]


@dataclass
class LedgerEntry:
    t: float
    kind: str  # deposit | issue | deliver | expire
    bits: int
    key_id: str | None = None
    direction: str | None = None
    note: str | None = None


class KME:
    def __init__(
        self,
        kme_id: str,
        sae_id: str,
        *,
        key_size: int = 256,
        max_key_count: int = 100_000,
        max_key_per_request: int = 128,
        max_key_size: int = 16_384,
        min_key_size: int = 128,
        clock=None,
    ):
        self.kme_id = kme_id
        self.sae_id = sae_id
        self.peer: KME | None = None
        self.key_size = key_size
        self.max_key_count = max_key_count
        self.max_key_per_request = max_key_per_request
        self.max_key_size = max_key_size
        self.min_key_size = min_key_size
        self._clock = clock or _now
        # keys I issue as master (master = my SAE) and keys the peer issues to me
        self._master_pool: OrderedDict[str, bytearray] = OrderedDict()
        self._slave_pool: OrderedDict[str, bytearray] = OrderedDict()
        self._reserved: dict[str, Reservation] = {}
        self._idempotent: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()
        self.ledger: deque[LedgerEntry] = deque(maxlen=2_000)
        self.counters = {"issued_bits": 0, "delivered_bits": 0, "deposited_bits": 0}

    # -- helpers -------------------------------------------------------------------

    @property
    def peer_sae_id(self) -> str:
        assert self.peer is not None
        return self.peer.sae_id

    def stored_bits(self, direction: str = "out") -> int:
        pool = self._master_pool if direction == "out" else self._slave_pool
        return len(pool) * BLOCK_BITS

    def _log(
        self,
        kind: str,
        bits: int,
        key_id: str | None = None,
        direction: str | None = None,
        note: str | None = None,
    ) -> None:
        self.ledger.append(LedgerEntry(self._clock(), kind, bits, key_id, direction, note))

    def _check_peer(self, other_sae: str) -> None:
        if other_sae != self.peer_sae_id:
            raise KMEError(
                400, "unknown SAE", [{"sae_id": f"{other_sae} is not served by this KME link"}]
            )

    # -- deposit from the QKD module --------------------------------------------------

    def deposit(self, direction: str, blocks: list[tuple[str, bytes]]) -> None:
        """``direction`` is "out" (I am master of these keys) or "in" (the peer is)."""
        pool = self._master_pool if direction == "out" else self._slave_pool
        for key_id, material in blocks:
            if len(material) != BLOCK_BYTES:
                raise ValueError("deposit blocks must be exactly one block long")
            pool[key_id] = bytearray(material)
        bits = len(blocks) * BLOCK_BITS
        self.counters["deposited_bits"] += bits
        self._log("deposit", bits, direction=direction)

    # -- ETSI GS QKD 014 -----------------------------------------------------------------

    def get_status(self, slave_sae_id: str) -> dict[str, Any]:
        self._check_peer(slave_sae_id)
        stored = self.stored_bits("out") // self.key_size
        return {
            "source_KME_ID": self.kme_id,
            "target_KME_ID": self.peer.kme_id,  # type: ignore[union-attr]
            "master_SAE_ID": self.sae_id,
            "slave_SAE_ID": slave_sae_id,
            "key_size": self.key_size,
            "stored_key_count": stored,
            "max_key_count": self.max_key_count,
            "max_key_per_request": self.max_key_per_request,
            "max_key_size": self.max_key_size,
            "min_key_size": self.min_key_size,
            "max_SAE_ID_count": 0,
        }

    def get_key(
        self,
        slave_sae_id: str,
        number: int | None = None,
        size: int | None = None,
        additional_slave_SAE_IDs: list[str] | None = None,
        extension_mandatory: list[dict[str, Any]] | None = None,
        extension_optional: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self._check_peer(slave_sae_id)
        number = 1 if number is None else number
        size = self.key_size if size is None else size
        if additional_slave_SAE_IDs:
            raise KMEError(400, "multicast is not supported", [{"max_SAE_ID_count": "0"}])
        if extension_mandatory:
            names = [next(iter(e), "?") for e in extension_mandatory]
            raise KMEError(
                400,
                "not all extension_mandatory parameters are supported",
                [{"extension_mandatory_unsupported": ", ".join(names)}],
            )
        if size % 8:
            raise KMEError(400, "size shall be a multiple of 8")
        if not self.min_key_size <= size <= self.max_key_size:
            raise KMEError(
                400, f"size must be between {self.min_key_size} and {self.max_key_size} bits"
            )
        if not 1 <= number <= self.max_key_per_request:
            raise KMEError(400, f"number must be between 1 and {self.max_key_per_request}")

        idem = _idempotency_key(extension_optional)
        cache_key = (slave_sae_id, idem) if idem else None
        if cache_key and cache_key in self._idempotent:
            return self._idempotent[cache_key]

        per_key = ceil(size / BLOCK_BITS)
        needed = number * per_key
        if len(self._master_pool) < needed:
            raise KMEError(
                503,
                "insufficient key material: run a QKD session to refill the key pool",
                [
                    {
                        "needed_bits": str(needed * BLOCK_BITS),
                        "available_bits": str(self.stored_bits("out")),
                    }
                ],
            )
        assert self.peer is not None
        keys = []
        issued: list[tuple[str, list[bytearray]]] = []
        try:
            for _ in range(number):
                ids, blocks = [], []
                for _ in range(per_key):
                    block_id, block = self._master_pool.popitem(last=False)
                    ids.append(block_id)
                    blocks.append(block)
                key_id = str(uuid.uuid4())
                # associate first: the slave's KME must know the key before the master does
                self.peer._reserve(
                    key_id, ids, Reservation(self.sae_id, self.peer.sae_id, size, [])
                )
                material = bytes(b"".join(blocks))[: size // 8]
                issued.append((key_id, blocks))
                keys.append({"key_ID": key_id, "key": base64.b64encode(material).decode()})
                self.counters["issued_bits"] += size
                self._log("issue", size, key_id, "out")
        except KMEError:
            raise
        finally:
            for _, blocks in issued:
                _zero(blocks)  # the master's copy lives only in the response now
        response = {"keys": keys}
        if cache_key:
            self._idempotent[cache_key] = response
            while len(self._idempotent) > 256:
                self._idempotent.popitem(last=False)
        return response

    def get_key_with_ids(
        self, master_sae_id: str, key_ids: list[str], caller_sae_id: str
    ) -> dict[str, Any]:
        self._check_peer(master_sae_id)
        reservations = []
        for key_id in key_ids:
            reservation = self._reserved.get(key_id)
            if reservation is None:
                raise KMEError(400, "one or more keys specified are not found on KME")
            if reservation.master_sae != master_sae_id or reservation.slave_sae != caller_sae_id:
                raise KMEError(401, "unauthorized")
            reservations.append((key_id, reservation))
        keys = []
        for key_id, reservation in reservations:
            del self._reserved[key_id]
            material = bytes(b"".join(reservation.blocks))[: reservation.size_bits // 8]
            keys.append({"key_ID": key_id, "key": base64.b64encode(material).decode()})
            _zero(reservation.blocks)
            self.counters["delivered_bits"] += reservation.size_bits
            self._log("deliver", reservation.size_bits, key_id, "in")
        return {"keys": keys}

    def _reserve(self, key_id: str, block_ids: list[str], template: Reservation) -> None:
        """Peer KME tells us which blocks it issued as ``key_id`` (the KME-to-KME association)."""
        blocks = []
        for block_id in block_ids:
            block = self._slave_pool.pop(block_id, None)
            if block is None:
                _zero(blocks)
                raise KMEError(503, "key pools of the two KMEs are out of sync")
            blocks.append(block)
        template.blocks = blocks
        self._reserved[key_id] = template

    # -- views for the UI (never contain key material) --------------------------------

    def snapshot(self) -> dict[str, Any]:
        return {
            "kme_id": self.kme_id,
            "sae_id": self.sae_id,
            "outgoing_bits": self.stored_bits("out"),
            "incoming_bits": self.stored_bits("in"),
            "reserved_keys": len(self._reserved),
            "reserved_bits": sum(r.size_bits for r in self._reserved.values()),
            **self.counters,
        }


def _now() -> float:
    import time

    return time.time()


def _idempotency_key(extension_optional: list[dict[str, Any]] | None) -> str | None:
    for ext in extension_optional or []:
        if "idempotency_key" in ext:
            return str(ext["idempotency_key"])
    return None


def link_kmes(a: KME, b: KME) -> None:
    a.peer, b.peer = b, a


def deposit_session_key(alice: KME, bob: KME, session_no: int, key: bytes) -> dict[str, int]:
    """Split fresh QKD key between the two directions and load both KMEs identically.

    Alice->Bob gets the first half and Bob->Alice the second, in whole blocks, so
    neither KME ever holds a block the other will also hand out in the other direction.
    """
    blocks_total = len(key) // BLOCK_BYTES
    half = blocks_total // 2
    out: dict[str, int] = {}
    for direction, start, count, master, slave in (
        ("a2b", 0, half, alice, bob),
        ("b2a", half, half, bob, alice),
    ):
        blocks = []
        for i in range(count):
            offset = (start + i) * BLOCK_BYTES
            block_id = str(uuid.uuid5(_NAMESPACE, f"{session_no}:{direction}:{i}"))
            blocks.append((block_id, key[offset : offset + BLOCK_BYTES]))
        master.deposit("out", blocks)
        slave.deposit("in", blocks)
        out[direction] = count * BLOCK_BITS
    return out
