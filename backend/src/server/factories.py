"""Turn API configuration into the objects the QKD engine uses."""

from __future__ import annotations

import math
from dataclasses import replace

from qkd.classical.channel import Message, Tamper
from qkd.classical.channel import pack_bits as _pack
from qkd.classical.channel import unpack_bits as _unpack
from qkd.quantum.attacks import EveBasis, InterceptResend, QuantumAttack
from qkd.quantum.channel import ChannelModel
from server.schemas import AttackConfig, ChannelConfig, TamperKind

_BASIS = {
    "random": EveBasis.RANDOM,
    "z": EveBasis.Z,
    "x": EveBasis.X,
    "breidbart": EveBasis.BREIDBART,
}


def make_channel(cfg: ChannelConfig) -> ChannelModel:
    return ChannelModel(
        length_km=cfg.length_km,
        attenuation_db_per_km=cfg.attenuation_db_per_km,
        detector_efficiency=cfg.detector_efficiency,
        dark_count_prob=cfg.dark_count_prob,
        depolarizing=cfg.depolarizing,
        misalignment_rad=math.radians(cfg.misalignment_deg),
        device=cfg.device,
    )


def make_attack(cfg: AttackConfig) -> QuantumAttack | None:
    if cfg.kind == "none":
        return None
    return InterceptResend(fraction=cfg.fraction, basis=_BASIS[cfg.basis])


def make_tamper(kind: TamperKind) -> Tamper | None:
    """Classical man-in-the-middle: Mallory edits public messages in flight."""
    if kind == "none":
        return None
    if kind == "flip_estimate":

        def flip_estimate(message: Message) -> Message:
            if message.kind != "estimate":
                return message
            payload = dict(message.payload)
            payload["errors"] = max(0, int(payload["errors"]) - 1) or int(payload["errors"]) + 1
            return replace(message, payload=payload)

        return flip_estimate

    def flip_bases(message: Message) -> Message:
        if message.kind != "alice_bases":
            return message
        bases = _unpack(message.payload["bases"])
        bases[:8] ^= 1
        return replace(message, payload={"bases": _pack(bases)})

    return flip_bases
