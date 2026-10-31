"""BB84 with finite-key analysis: Alice and Bob as concurrent parties.

Following Tomamichel, Lim, Gisin, Renner (2012): the key comes from n sifted
bits in the X basis, the channel is tested on k sifted bits in the Z basis, the
session aborts if the Z-sample error exceeds Q_tol, and the final key length is
the finite-key bound for the measured leakage. Signals are sent in chunks until
both counts are reached.

The two parties only share (a) the quantum medium, where each sees only its
own lab's data, and (b) a public classical channel whose whole transcript is
Wegman-Carter authenticated. :func:`run_bb84` plays the role of the world: it
wires them together, starts both, and collects the simulator's omniscient
record (for the UI's "what Eve knows" panel and for tests).
"""

from __future__ import annotations

import asyncio
import binascii
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from numpy.typing import NDArray

from qkd.auth.keypool import AuthKeyExhausted, AuthKeyPool
from qkd.auth.transcript import TranscriptAuthenticator
from qkd.classical.channel import (
    ClassicalChannel,
    ProtocolAbort,
    Tamper,
    pack_bits,
    unpack_bits,
)
from qkd.protocol.events import Emit, Event, null_emit
from qkd.protocol.finite_key import h2, key_length, union_bound_bits
from qkd.protocol.medium import MediumHub
from qkd.protocol.params import SessionParams
from qkd.protocol.session import PostResult, Wire, alice_postprocess, bob_postprocess
from qkd.quantum.prepare_measure import PrepareMeasureLink
from qkd.randomness import Randomness

Bits = NDArray[np.uint8]
KEY_BASIS = 1  # X
TEST_BASIS = 0  # Z


@dataclass
class _Sifted:
    """Bits kept after sifting, one list entry per chunk."""

    key: list[Bits] = field(default_factory=list)  # bits measured in X, bases matched
    test: list[Bits] = field(default_factory=list)  # bits measured in Z, bases matched
    key_slots: list[NDArray[np.int64]] = field(default_factory=list)  # (chunk, slot) per key bit
    n_key: int = 0
    n_test: int = 0
    sent: int = 0
    detected: int = 0

    def add(
        self, chunk: int, bits: Bits, bases: Bits, detected: NDArray[np.bool_], partner_bases: Bits
    ) -> None:
        """``bits`` / ``bases`` are this party's per-slot values; ``partner_bases`` covers detected slots."""
        slots = np.flatnonzero(detected)
        match = bases[slots] == partner_bases
        in_key = match & (bases[slots] == KEY_BASIS)
        in_test = match & (bases[slots] == TEST_BASIS)
        self.key.append(bits[slots][in_key])
        self.test.append(bits[slots][in_test])
        key_slots = slots[in_key]
        self.key_slots.append(np.stack([np.full(key_slots.size, chunk), key_slots], axis=1))
        self.n_key += int(in_key.sum())
        self.n_test += int(in_test.sum())
        self.detected += int(slots.size)
        self.sent += int(bits.size)


def _select(n_available: int, n_wanted: int, rand: Randomness) -> NDArray[np.bool_]:
    """Random subset mask of exactly ``n_wanted`` of ``n_available`` positions."""
    chosen = np.argsort(rand.uniform(n_available), kind="stable")[:n_wanted]
    mask = np.zeros(n_available, dtype=bool)
    mask[chosen] = True
    return mask


def _policy(params: SessionParams):
    extra = union_bound_bits(params.leak_budget)

    def policy(leak_ec: int):
        return key_length(
            params.n_key,
            params.k_test,
            params.q_tol,
            leak_ec,
            params.eps_sec,
            params.eps_cor,
            extra_cost=extra,
        )

    return policy


async def _sift(
    w: Wire,
    params: SessionParams,
    hub: MediumHub,
    rand: Randomness,
    is_alice: bool,
) -> tuple[_Sifted, list[Bits], list[Bits]]:
    """Chunks of quantum transmission plus basis announcement until n and k are reached."""
    sifted = _Sifted()
    all_bits: list[Bits] = []
    all_bases: list[Bits] = []
    chunk = 0
    while sifted.n_key < params.n_key or sifted.n_test < params.k_test:
        if sifted.sent >= params.max_signals:
            await w.abort(
                "quantum",
                "not enough signals reached Bob's detectors (the link is too lossy for the "
                "signal budget)",
                sent=sifted.sent,
                sifted_key=sifted.n_key,
                sifted_test=sifted.n_test,
            )
        w.stage_begin("quantum")
        size = min(params.chunk, params.max_signals - sifted.sent)
        medium = hub.medium(chunk)
        bases = rand.choice_bits(size, params.p_x)  # 1 = X (key basis), 0 = Z (test basis)
        if is_alice:
            bits = rand.bits(size)
            await medium.alice_send(bits, bases)
            if chunk == 0:
                m = params.preview_signals
                w.emit(
                    "quantum", "alice_prepared", bits=bits[:m].tolist(), bases=bases[:m].tolist()
                )
            w.stage_end("quantum")
            w.stage_begin("sifting")
            msg = (await w.recv("detections")).payload
            detected = unpack_bits(msg["mask"]).astype(bool)[:size]
            bob_bases = unpack_bits(msg["bases"])
            if detected.size != size or bob_bases.size != int(detected.sum()):
                raise ValueError("malformed detection report")
            await w.send("alice_bases", {"bases": pack_bits(bases[detected])})
        else:
            observation = await medium.bob_measure(bases)
            detected = observation.detected
            bits = np.where(observation.bits >= 0, observation.bits, 0).astype(np.uint8)
            if chunk == 0:
                m = params.preview_signals
                w.emit(
                    "quantum",
                    "bob_measured",
                    bases=bases[:m].tolist(),
                    detected=detected[:m].astype(int).tolist(),
                    bits=observation.bits[:m].tolist(),
                )
            w.stage_end("quantum")
            w.stage_begin("sifting")
            await w.send(
                "detections", {"mask": pack_bits(detected), "bases": pack_bits(bases[detected])}
            )
            msg = (await w.recv("alice_bases")).payload
            alice_bases = unpack_bits(msg["bases"])
            if alice_bases.size != int(detected.sum()):
                raise ValueError("malformed basis announcement")
            bob_bases = bases[detected]
        # Matching is decided from the two public basis lists; each party keeps its own bits.
        partner_bases = bob_bases if is_alice else alice_bases
        sifted.add(chunk, bits, bases, detected, partner_bases)
        all_bits.append(bits)
        all_bases.append(bases)
        w.emit(
            "sifting",
            "chunk",
            chunk=chunk,
            sent=sifted.sent,
            detected=sifted.detected,
            key_bits=sifted.n_key,
            test_bits=sifted.n_test,
            target_key=params.n_key,
            target_test=params.k_test,
        )
        w.stage_end("sifting")
        chunk += 1
    return sifted, all_bits, all_bases


def _guard(coro_fn):
    """Turn garbage caused by an active attacker into a clean abort instead of a crash."""

    async def wrapper(w: Wire, *args, **kwargs):
        try:
            return await coro_fn(w, *args, **kwargs)
        except (KeyError, ValueError, TypeError, IndexError, binascii.Error) as exc:
            try:
                await w.abort(
                    "protocol", f"malformed or inconsistent message ({type(exc).__name__})"
                )
            except ProtocolAbort as abort:
                raise abort from exc

    return wrapper


@_guard
async def _alice(w, params, hub, rand) -> tuple[PostResult, dict[str, Any]]:
    sifted, all_bits, all_bases = await _sift(w, params, hub, rand, is_alice=True)

    # Choose the n key bits and k test bits at random from what was sifted.
    w.stage_begin("estimation")
    key_all = np.concatenate(sifted.key)
    test_all = np.concatenate(sifted.test)
    key_mask = _select(key_all.size, params.n_key, rand)
    test_mask = _select(test_all.size, params.k_test, rand)
    await w.send("select", {"key": pack_bits(key_mask), "test": pack_bits(test_mask)})
    key = key_all[key_mask]
    test_bits = test_all[test_mask]
    key_slots = np.concatenate(sifted.key_slots)[key_mask]

    await w.send("test_bits", {"bits": pack_bits(test_bits)})
    estimate = (await w.recv("estimate")).payload
    errors = int(estimate["errors"])
    qber = errors / params.k_test
    w.emit(
        "estimation",
        "result",
        errors=errors,
        sample=params.k_test,
        qber=qber,
        threshold=params.q_tol,
    )
    w.stage_end("estimation")

    post = await alice_postprocess(w, params, key, max(qber, 0.0), _policy(params), rand)
    truth = {
        "key_slots": key_slots,
        "bases": all_bases,
        "bits": all_bits,
        "raw_key": key,
        "sent": sifted.sent,
        "detected": sifted.detected,
        "sifted_key": sifted.n_key,
        "sifted_test": sifted.n_test,
        "qber": qber,
        "errors": errors,
    }
    return post, truth


@_guard
async def _bob(w, params, hub, rand) -> tuple[PostResult, dict[str, Any]]:
    sifted, _, _ = await _sift(w, params, hub, rand, is_alice=False)

    w.stage_begin("estimation")
    key_all = np.concatenate(sifted.key)
    test_all = np.concatenate(sifted.test)
    selection = (await w.recv("select")).payload
    key_mask = unpack_bits(selection["key"]).astype(bool)
    test_mask = unpack_bits(selection["test"]).astype(bool)
    if (
        key_mask.size != key_all.size
        or test_mask.size != test_all.size
        or int(key_mask.sum()) != params.n_key
        or int(test_mask.sum()) != params.k_test
    ):
        raise ValueError("inconsistent selection")
    key = key_all[key_mask]
    test_bits = test_all[test_mask]
    alice_test = unpack_bits((await w.recv("test_bits")).payload["bits"])
    if alice_test.size != test_bits.size:
        raise ValueError("wrong number of test bits")
    errors = int(np.count_nonzero(alice_test != test_bits))
    qber = errors / params.k_test
    if qber > params.q_tol:
        await w.abort(
            "estimation",
            "the channel test measured more errors than the tolerance allows: "
            "someone may be listening, or the line is too noisy",
            errors=errors,
            sample=params.k_test,
            qber=qber,
            threshold=params.q_tol,
        )
    await w.send("estimate", {"errors": errors})
    w.stage_end("estimation")

    post = await bob_postprocess(w, params, key, _policy(params))
    return post, {"qber": qber, "errors": errors}


@dataclass
class SessionResult:
    ok: bool
    key: bytes | None  # delivered key (authentication refill already set aside)
    key_bits: int
    abort: dict[str, Any] | None
    stats: dict[str, Any]
    ground_truth: dict[str, Any]  # simulator-only, omniscient
    events: list[Event]


def _bits_to_bytes(bits: Bits) -> bytes:
    usable = bits.size - bits.size % 8
    return np.packbits(bits[:usable]).tobytes()


async def run_bb84(
    params: SessionParams,
    link: PrepareMeasureLink,
    alice_pool: AuthKeyPool,
    bob_pool: AuthKeyPool,
    *,
    tamper: Tamper | None = None,
    taps: Iterable = (),
    emit: Emit = null_emit,
    seed: int | None = None,
    timeout_s: float = 120.0,
) -> SessionResult:
    """Run one full BB84 key-establishment session and update both authentication pools."""
    events: list[Event] = []

    def record(event: Event) -> None:
        events.append(event)
        emit(event)

    started = time.perf_counter()
    channel = ClassicalChannel(taps=list(taps), tamper=tamper, timeout_s=timeout_s)

    def on_transmission(chunk: int, tx) -> None:
        """Simulator-only record of Eve's actions on the first signals (shown, labelled, in the lab)."""
        if chunk == 0 and tx.eve is not None:
            m = params.preview_signals
            record(
                Event(
                    "quantum",
                    "eve_acted",
                    {
                        "actions": tx.eve.action[:m].tolist(),
                        "outcomes": tx.eve.outcome[:m].tolist(),
                        "attack": link.attack.describe() if link.attack else None,
                        "simulator_only": True,
                    },
                )
            )

    hub = MediumHub(link, on_transmission)
    alice_rand = Randomness(seed)
    bob_rand = Randomness(seed, stream=1)

    def abort_result(stage: str, reason: str, detail: dict[str, Any]) -> SessionResult:
        record(Event("result", "abort", {"stage": stage, "reason": reason, **detail}))
        return SessionResult(
            False,
            None,
            0,
            {"stage": stage, "reason": reason, "detail": detail},
            _stats(channel, started, params),
            {},
            events,
        )

    try:
        auth_keys = (alice_pool.take(params.auth_key_bytes), bob_pool.take(params.auth_key_bytes))
    except AuthKeyExhausted as exc:
        return abort_result("authentication", str(exc), {})

    record(Event("quantum", "start", {"protocol": "bb84", "params": _public_params(params)}))
    wa = Wire(
        "alice", channel, TranscriptAuthenticator(auth_keys[0], params.auth_checkpoints), record
    )
    wb = Wire(
        "bob", channel, TranscriptAuthenticator(auth_keys[1], params.auth_checkpoints), record
    )
    alice_task = asyncio.create_task(_alice(wa, params, hub, alice_rand))
    bob_task = asyncio.create_task(_bob(wb, params, hub, bob_rand))
    a_res, b_res = await asyncio.gather(alice_task, bob_task, return_exceptions=True)

    for res in (a_res, b_res):
        if isinstance(res, ProtocolAbort):
            return abort_result(res.stage, res.reason, res.detail)
    for res in (a_res, b_res):
        if isinstance(res, BaseException):
            raise res

    (alice_post, truth), (bob_post, _) = a_res, b_res
    refill = params.auth_refill_bits
    if alice_post.secret.size != bob_post.secret.size or not np.array_equal(
        alice_post.secret, bob_post.secret
    ):
        return abort_result("verification", "final keys differ (probability below eps_cor)", {})
    secret = alice_post.secret
    alice_pool.replenish(_bits_to_bytes(secret[:refill]))
    bob_pool.replenish(_bits_to_bytes(secret[:refill]))
    key = _bits_to_bytes(secret[refill:])

    stats = _stats(channel, started, params)
    stats.update(alice_post.stats)
    stats.update(
        sent=truth["sent"],
        detected=truth["detected"],
        sifted_key=truth["sifted_key"],
        sifted_test=truth["sifted_test"],
        qber=truth["qber"],
        errors=truth["errors"],
        key_error_rate=bob_post.stats["key_error_rate"],
        timings={
            **{f"alice_{k}": v for k, v in wa.timings.items()},
            **{f"bob_{k}": v for k, v in wb.timings.items()},
        },
        auth_burned_bytes=params.auth_key_bytes,
        auth_refill_bits=refill,
        delivered_key_bits=len(key) * 8,
        p_x=params.p_x,
    )
    ground_truth = _eve_ground_truth(link, hub, truth, params)
    record(Event("result", "success", {"key_bits": len(key) * 8, "stats": _brief(stats)}))
    return SessionResult(True, key, len(key) * 8, None, stats, ground_truth, events)


def _public_params(p: SessionParams) -> dict[str, Any]:
    return {
        "n_key": p.n_key,
        "k_test": p.k_test,
        "q_tol": p.q_tol,
        "eps_sec": p.eps_sec,
        "eps_cor": p.eps_cor,
        "p_x": p.p_x,
        "chunk": p.chunk,
    }


def _brief(stats: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "sent",
        "detected",
        "sifted_key",
        "sifted_test",
        "qber",
        "leak_ec",
        "delivered_key_bits",
        "elapsed_s",
    )
    return {k: stats[k] for k in keys if k in stats}


def _stats(channel: ClassicalChannel, started: float, params: SessionParams) -> dict[str, Any]:
    return {
        "classical_bytes": channel.bytes_sent,
        "classical_messages": channel.messages_sent,
        "elapsed_s": time.perf_counter() - started,
        "auth_burned_bytes": params.auth_key_bytes,
    }


def _eve_ground_truth(
    link: PrepareMeasureLink, hub: MediumHub, truth: dict[str, Any], params: SessionParams
) -> dict[str, Any]:
    """What the simulator knows about Eve's information on the raw key (never available to real users)."""
    out: dict[str, Any] = {"attack": link.attack.describe() if link.attack else None}
    if link.attack is None:
        out.update(eve_attempted=0, eve_correct=0, eve_info_bits=0.0)
        return out
    slots = truth["key_slots"]
    attempted = correct = 0
    for chunk, medium in hub.media.items():
        tx = medium.transmission
        if tx is None or tx.eve is None:
            continue
        sel = slots[slots[:, 0] == chunk, 1]
        guesses = tx.eve.guesses(link.attack, truth["bases"][chunk].astype(np.int8))[sel]
        actual = truth["bits"][chunk][sel]
        known = guesses >= 0
        attempted += int(known.sum())
        correct += int((guesses[known] == actual[known]).sum())
    accuracy = correct / attempted if attempted else 0.0
    info = attempted * (1 - h2(1 - accuracy)) if attempted else 0.0
    out.update(
        eve_attempted=attempted,
        eve_correct=correct,
        eve_guess_accuracy=accuracy,
        eve_info_bits=info,
        eve_info_fraction=info / params.n_key,
    )
    return out
