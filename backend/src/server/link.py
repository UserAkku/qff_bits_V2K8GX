"""The QKD link between Alice's and Bob's sites: standing configuration, sessions, and key hand-off.

One link owns the shared authentication pool (provisioned out of band), the
standing channel / Eve configuration, and the two KMEs. Sessions run one at a
time so both authentication pools stay in lock-step; a successful session
deposits its key into both KMEs.
"""

from __future__ import annotations

import asyncio
import math
import os
import secrets
import time
from collections import OrderedDict
from dataclasses import asdict, is_dataclass
from typing import Any

import numpy as np

from qkd.auth.keypool import AuthKeyPool
from qkd.protocol.bb84 import run_bb84
from qkd.protocol.events import Event
from qkd.protocol.params import SessionParams
from qkd.quantum.prepare_measure import PrepareMeasureLink
from server.factories import make_attack, make_channel, make_tamper
from server.kme import KME, deposit_session_key, link_kmes
from server.schemas import AttackConfig, ChannelConfig, LinkConfigUpdate, SessionRequest, TamperKind

ALICE_SAE, BOB_SAE = "sae-alice", "sae-bob"
ALICE_KME, BOB_KME = "kme-alice", "kme-bob"
PRESHARED_BYTES = 2_048  # authentication secret handed over in person when the link was installed


def jsonable(x: Any) -> Any:
    if isinstance(x, dict):
        return {str(k): jsonable(v) for k, v in x.items()}
    if isinstance(x, list | tuple | set):
        return [jsonable(v) for v in x]
    if isinstance(x, np.ndarray):
        return jsonable(x.tolist())
    if isinstance(x, np.generic):
        return jsonable(x.item())
    if isinstance(x, bytes | bytearray):
        return bytes(x).hex()
    if is_dataclass(x) and not isinstance(x, type):
        return jsonable(asdict(x))
    if isinstance(x, float) and not math.isfinite(x):
        return None
    return x


class SessionRecord:
    def __init__(self, session_id: str, number: int, request: dict[str, Any]):
        self.id = session_id
        self.number = number
        self.request = request
        self.status = "queued"  # queued | running | success | aborted | error
        self.events: list[dict[str, Any]] = []
        self.result: dict[str, Any] | None = None
        self.created = time.time()
        self._subscribers: list[asyncio.Queue[dict[str, Any] | None]] = []
        self.task: asyncio.Task[None] | None = None

    def publish(
        self, stage: str, kind: str, data: dict[str, Any] | None = None, t: float | None = None
    ) -> None:
        event = {
            "stage": stage,
            "kind": kind,
            "data": jsonable(data or {}),
            "t": t or time.time(),
            "session": self.id,
        }
        self.events.append(event)
        for queue in self._subscribers:
            queue.put_nowait(event)

    def finish(self) -> None:
        for queue in self._subscribers:
            queue.put_nowait(None)

    async def stream(self):
        """Replay everything so far, then follow live until the session ends."""
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        backlog = list(self.events)
        done = self.status in ("success", "aborted", "error")
        if not done:
            self._subscribers.append(queue)
        try:
            for event in backlog:
                yield event
            while not done:
                event = await queue.get()
                if event is None:
                    break
                yield event
        finally:
            if queue in self._subscribers:
                self._subscribers.remove(queue)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "number": self.number,
            "status": self.status,
            "created": self.created,
            "request": self.request,
            "result": self.result,
        }


class QKDLink:
    def __init__(self, preshared_bytes: int = PRESHARED_BYTES):
        self.kme_alice = KME(ALICE_KME, ALICE_SAE)
        self.kme_bob = KME(BOB_KME, BOB_SAE)
        link_kmes(self.kme_alice, self.kme_bob)
        self.channel = ChannelConfig()
        self.attack = AttackConfig()
        self.tamper: TamperKind = "none"
        self.sessions: OrderedDict[str, SessionRecord] = OrderedDict()
        self._lock = asyncio.Lock()
        self._counter = 0
        self.provision(preshared_bytes)

    # -- provisioning -----------------------------------------------------------------

    def provision(self, n_bytes: int = PRESHARED_BYTES) -> None:
        """Install a fresh pre-shared authentication secret in both sites."""
        secret = os.urandom(n_bytes)
        self.alice_pool = AuthKeyPool.from_preshared(secret)
        self.bob_pool = AuthKeyPool.from_preshared(secret)

    def configure(self, update: LinkConfigUpdate) -> None:
        if update.channel is not None:
            self.channel = update.channel
        if update.attack is not None:
            self.attack = update.attack
        if update.tamper is not None:
            self.tamper = update.tamper

    # -- sessions -----------------------------------------------------------------------

    def start(self, request: SessionRequest) -> SessionRecord:
        self._counter += 1
        record = SessionRecord(secrets.token_hex(6), self._counter, request.model_dump(mode="json"))
        self.sessions[record.id] = record
        while len(self.sessions) > 50:
            self.sessions.popitem(last=False)
        record.task = asyncio.create_task(self._run(record, request))
        return record

    async def _run(self, record: SessionRecord, request: SessionRequest) -> None:
        async with self._lock:
            record.status = "running"
            channel_cfg = request.channel or self.channel
            attack_cfg = request.attack or self.attack
            tamper_kind = request.tamper or self.tamper
            record.request.update(
                channel=channel_cfg.model_dump(mode="json"),
                attack=attack_cfg.model_dump(mode="json"),
                tamper=tamper_kind,
            )
            params = SessionParams(n_key=request.n_key, k_test=request.k_test, q_tol=request.q_tol)
            link = PrepareMeasureLink(
                make_channel(channel_cfg), make_attack(attack_cfg), seed=request.seed
            )

            def emit(event: Event) -> None:
                record.publish(event.stage, event.kind, event.data, event.t)

            record.publish(
                "session", "queued", {"number": record.number, "request": record.request}
            )
            try:
                result = await run_bb84(
                    params,
                    link,
                    self.alice_pool,
                    self.bob_pool,
                    tamper=make_tamper(tamper_kind),
                    emit=emit,
                    seed=request.seed,
                )
            except Exception as exc:  # a bug must not wedge the link
                record.status = "error"
                record.result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                record.publish("result", "error", record.result)
                record.finish()
                return

            deposited: dict[str, int] = {}
            if result.ok and result.key:
                deposited = deposit_session_key(
                    self.kme_alice, self.kme_bob, record.number, result.key
                )
            record.status = "success" if result.ok else "aborted"
            record.result = jsonable(
                {
                    "ok": result.ok,
                    "key_bits": result.key_bits,
                    "abort": result.abort,
                    "stats": result.stats,
                    "ground_truth": {k: v for k, v in result.ground_truth.items()},
                    "deposited_bits": deposited,
                    "auth_pool_bytes": self.alice_pool.available,
                }
            )
            record.publish(
                "kme", "deposit", {"deposited_bits": deposited, **self.snapshot()["kme"]}
            )
            record.publish("session", "finished", {"status": record.status})
            record.finish()

    # -- views ----------------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        return jsonable(
            {
                "config": {
                    "channel": self.channel.model_dump(mode="json"),
                    "attack": self.attack.model_dump(mode="json"),
                    "tamper": self.tamper,
                },
                "auth_pool": {
                    "alice_bytes": self.alice_pool.available,
                    "bob_bytes": self.bob_pool.available,
                    "consumed": self.alice_pool.consumed,
                    "replenished": self.alice_pool.replenished,
                },
                "kme": {"alice": self.kme_alice.snapshot(), "bob": self.kme_bob.snapshot()},
                "busy": self._lock.locked(),
            }
        )
