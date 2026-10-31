"""Machinery shared by the QKD protocols: the authenticated wire and the post-processing stages.

After sifting and parameter estimation every protocol ends the same way, with
Alice as the reference and Bob as the party that corrects:

1. Cascade error reconciliation (every parity disclosed is counted),
2. error verification with a 2-universal hash of ceil(log2(1/eps_cor)) bits,
3. authentication checkpoint 0 (the classical transcript so far is genuine),
4. privacy amplification with a Toeplitz hash to the finite-key length,
5. authentication checkpoint 1 (including the amplification parameters).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np
from numpy.typing import NDArray

from qkd.auth.transcript import TranscriptAuthenticator
from qkd.classical.channel import (
    ClassicalChannel,
    Message,
    ProtocolAbort,
    Role,
    pack_bits,
    unpack_bits,
)
from qkd.postprocessing.cascade import (
    CascadeAlice,
    CascadeBob,
    ParityQuery,
    block_sizes,
    shuffles,
)
from qkd.postprocessing.toeplitz import seed_length, toeplitz_hash
from qkd.protocol.events import Emit, Event
from qkd.protocol.finite_key import KeyLengthBreakdown, h2
from qkd.protocol.params import SessionParams
from qkd.randomness import Randomness

Bits = NDArray[np.uint8]
KeyLengthPolicy = Callable[[int], KeyLengthBreakdown]  # leak_EC -> allowed key length


class Wire:
    """One party's end of the classical channel: sends, receives and absorbs into the transcript MAC."""

    def __init__(
        self,
        role: Role,
        channel: ClassicalChannel,
        auth: TranscriptAuthenticator,
        emit: Emit,
    ):
        self.role = role
        self.channel = channel
        self.auth = auth
        self._emit = emit
        self.timings: dict[str, float] = {}
        self._stage_started: dict[str, float] = {}

    def emit(self, stage: str, kind: str, **data: Any) -> None:
        self._emit(Event(stage, kind, data))

    def stage_begin(self, stage: str) -> None:
        self._stage_started[stage] = time.perf_counter()

    def stage_end(self, stage: str) -> None:
        began = self._stage_started.pop(stage, None)
        if began is not None:
            self.timings[stage] = self.timings.get(stage, 0.0) + time.perf_counter() - began

    async def send(
        self, kind: str, payload: dict[str, Any], *, authenticated: bool = True
    ) -> Message:
        message = await self.channel.send(self.role, kind, payload)
        if authenticated:
            self.auth.absorb(message)
        return message

    async def recv(self, kind: str | tuple[str, ...], *, authenticated: bool = True) -> Message:
        message = await self.channel.receive(self.role, kind)
        if authenticated:
            self.auth.absorb(message)
        return message

    async def abort(self, stage: str, reason: str, **detail: Any) -> None:
        await self.channel.send(self.role, "abort", {"stage": stage, "reason": reason, **detail})
        raise ProtocolAbort(reason, stage, detail)

    async def checkpoint(self, index: int, speaks_first: bool) -> None:
        """Exchange Wegman-Carter tags over the transcript; any tampering shows up as a mismatch."""
        other: Role = "bob" if self.role == "alice" else "alice"
        kind = f"auth{index}"

        async def send_mine() -> None:
            tag = self.auth.tag(index, self.role)
            await self.send(kind, {"tag": tag.hex()}, authenticated=False)

        async def check_theirs() -> None:
            message = await self.recv(kind, authenticated=False)
            tag = bytes.fromhex(message.payload["tag"])
            if not self.auth.verify(index, other, tag):
                await self.abort(
                    "authentication",
                    "the classical-channel transcript does not match: a message was modified, "
                    "dropped, reordered or injected",
                    checkpoint=index,
                )

        if speaks_first:
            await send_mine()
            await check_theirs()
        else:
            await check_theirs()
            await send_mine()
        self.emit(
            "authentication", "checkpoint", index=index, forgery_bound=self.auth.forgery_bound
        )


@dataclass
class PostResult:
    secret: Bits  # privacy-amplified key before the authentication refill is set aside
    stats: dict[str, Any] = field(default_factory=dict)


def _flatten(queries: list[ParityQuery]) -> list[int]:
    return [v for q in queries for v in (q.pass_index, q.start, q.end)]


def _unflatten(flat: list[int], passes: int, n: int) -> list[ParityQuery]:
    if len(flat) % 3:
        raise ValueError("malformed parity query list")
    out = []
    for i in range(0, len(flat), 3):
        p, s, e = (int(v) for v in flat[i : i + 3])
        if not (0 <= p < passes and 0 <= s < e <= n):
            raise ValueError("parity query out of range")
        out.append(ParityQuery(p, s, e))
    return out


async def alice_postprocess(
    w: Wire,
    params: SessionParams,
    key: Bits,
    q_est: float,
    policy: KeyLengthPolicy,
    rand: Randomness,
) -> PostResult:
    n = int(key.size)
    passes = params.cascade_passes
    stats: dict[str, Any] = {}

    # 1. error reconciliation (Alice only answers parity questions)
    w.stage_begin("reconciliation")
    seed = rand.seed_int() >> 1
    await w.send("ec_start", {"seed": seed, "qber": q_est, "passes": passes, "n": n})
    alice = CascadeAlice(key, shuffles(seed, n, passes))
    rounds = 0
    while True:
        message = await w.recv(("ec_queries", "ec_done"))
        if message.kind == "ec_done":
            break
        queries = _unflatten(message.payload["q"], passes, n)
        await w.send("ec_answers", {"a": pack_bits(np.asarray(alice.answer(queries), np.uint8))})
        rounds += 1
        w.emit("reconciliation", "round", round=rounds, parities=alice.revealed)
    leak_ec = alice.revealed
    w.stage_end("reconciliation")

    # 2. verification: tag of Alice's key under a public 2-universal hash
    w.stage_begin("verification")
    t = params.verification_bits
    v_seed = rand.bits(seed_length(n, t))
    tag = toeplitz_hash(v_seed, key, t)
    await w.send("verify", {"seed": pack_bits(v_seed), "tag": pack_bits(tag)})
    await w.recv("verified")
    w.emit("verification", "ok", tag_bits=t)
    w.stage_end("verification")

    # 3. checkpoint 0 gates privacy amplification on a genuine transcript
    w.stage_begin("authentication")
    await w.checkpoint(0, speaks_first=True)
    w.stage_end("authentication")

    # 4. privacy amplification
    w.stage_begin("amplification")
    breakdown = policy(leak_ec)
    length = breakdown.length
    if length < params.auth_refill_bits + params.min_key_bits:
        await w.abort(
            "amplification",
            "no secure key of useful length can be extracted at this error rate and block size",
            allowed_length=length,
            required=params.auth_refill_bits + params.min_key_bits,
            leak_ec=leak_ec,
        )
    pa_seed = rand.bits(seed_length(n, length))
    await w.send("amplify", {"length": length, "seed": pack_bits(pa_seed)})
    secret = toeplitz_hash(pa_seed, key, length)
    w.emit("amplification", "done", input_bits=n, output_bits=length, leak_ec=leak_ec)
    w.stage_end("amplification")

    # 5. checkpoint 1 covers the amplification parameters
    w.stage_begin("authentication")
    await w.checkpoint(1, speaks_first=True)
    w.stage_end("authentication")

    stats.update(
        leak_ec=leak_ec,
        ec_rounds=rounds,
        verification_bits=t,
        key_length=asdict(breakdown),
        reconciliation_efficiency=leak_ec / (n * h2(max(q_est, 1e-6))),
    )
    return PostResult(secret, stats)


async def bob_postprocess(
    w: Wire, params: SessionParams, key: Bits, policy: KeyLengthPolicy
) -> PostResult:
    n = int(key.size)
    passes = params.cascade_passes
    stats: dict[str, Any] = {}

    # 1. error reconciliation (Bob corrects his key towards Alice's)
    w.stage_begin("reconciliation")
    start = (await w.recv("ec_start")).payload
    if int(start["n"]) != n or int(start["passes"]) != passes:
        await w.abort("reconciliation", "reconciliation parameters do not match the session")
    q_est = float(start["qber"])
    bob = CascadeBob(key, shuffles(int(start["seed"]), n, passes), block_sizes(q_est, n, passes))
    while queries := bob.next_queries():
        if bob.leaked_bits > params.leak_budget:
            await w.abort(
                "reconciliation",
                "error correction would disclose too much information: the key-basis error "
                "rate is far above what the channel test promised",
                leaked=bob.leaked_bits,
                budget=params.leak_budget,
            )
        await w.send("ec_queries", {"q": _flatten(queries)})
        answers = unpack_bits((await w.recv("ec_answers")).payload["a"])
        if answers.size < len(queries):
            raise ValueError("too few parity answers")
        bob.receive([int(a) for a in answers[: len(queries)]])
        w.emit("reconciliation", "round", round=bob.rounds, parities=bob.leaked_bits)
    await w.send("ec_done", {})
    corrected = int(np.count_nonzero(bob.key != key))
    leak_ec = bob.leaked_bits
    w.emit(
        "reconciliation",
        "done",
        leaked=leak_ec,
        corrected=corrected,
        rounds=bob.rounds,
        passes=[asdict(p) for p in bob.stats],
        key_error_rate=corrected / n,
    )
    w.stage_end("reconciliation")

    # 2. verification
    w.stage_begin("verification")
    t = params.verification_bits
    message = (await w.recv("verify")).payload
    v_seed, alice_tag = unpack_bits(message["seed"]), unpack_bits(message["tag"])
    if v_seed.size != seed_length(n, t) or alice_tag.size != t:
        raise ValueError("malformed verification message")
    if not np.array_equal(toeplitz_hash(v_seed, bob.key, t), alice_tag):
        await w.abort(
            "verification",
            "the two keys still differ after error correction (the error rate in the key "
            "basis was too high to reconcile)",
            corrected=corrected,
            key_error_rate=corrected / n,
        )
    await w.send("verified", {})
    w.stage_end("verification")

    # 3. checkpoint 0
    w.stage_begin("authentication")
    await w.checkpoint(0, speaks_first=False)
    w.stage_end("authentication")

    # 4. privacy amplification
    w.stage_begin("amplification")
    breakdown = policy(leak_ec)
    message = (await w.recv("amplify")).payload
    length = int(message["length"])
    pa_seed = unpack_bits(message["seed"])
    if length != breakdown.length or pa_seed.size != seed_length(n, length):
        await w.abort("amplification", "Alice and Bob disagree about the secure key length")
    secret = toeplitz_hash(pa_seed, bob.key, length)
    w.stage_end("amplification")

    # 5. checkpoint 1
    w.stage_begin("authentication")
    await w.checkpoint(1, speaks_first=False)
    w.stage_end("authentication")

    stats.update(leak_ec=leak_ec, key_error_rate=corrected / n, corrected=corrected)
    return PostResult(secret, stats)
