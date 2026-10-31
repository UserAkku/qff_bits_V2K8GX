"""Request/response models for the control API (the ETSI 014 models live in the KME router)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Protocol = Literal["bb84"]
DeviceName = Literal[
    "FakeTorino", "FakeFez", "FakeKingston", "FakeMarrakesh", "FakeBrisbane", "FakeSherbrooke"
]


class ChannelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    length_km: float = Field(0.0, ge=0, le=300)
    attenuation_db_per_km: float = Field(0.2, ge=0, le=1)
    detector_efficiency: float = Field(1.0, gt=0, le=1)
    dark_count_prob: float = Field(0.0, ge=0, le=0.1)
    depolarizing: float = Field(0.0, ge=0, le=0.5)
    misalignment_deg: float = Field(0.0, ge=0, le=45)
    device: DeviceName | None = None


class AttackConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["none", "intercept_resend"] = "none"
    fraction: float = Field(1.0, ge=0, le=1)
    basis: Literal["random", "z", "x", "breidbart"] = "random"


TamperKind = Literal["none", "flip_estimate", "flip_bases"]


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: Protocol = "bb84"
    n_key: int = Field(8_192, ge=1_024, le=65_536)
    k_test: int = Field(4_096, ge=512, le=32_768)
    q_tol: float = Field(0.07, gt=0.005, lt=0.2)
    seed: int | None = Field(
        None, ge=0, le=2**31
    )  # seeded runs are for experiments, not for live keys
    # Anything left unset inherits the link's standing configuration.
    channel: ChannelConfig | None = None
    attack: AttackConfig | None = None
    tamper: TamperKind | None = None


class LinkConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: ChannelConfig | None = None
    attack: AttackConfig | None = None
    tamper: TamperKind | None = None


class RelayConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["honest", "flip_ciphertext", "replay_last", "drop"] = "honest"


class Envelope(BaseModel):
    """What the chat relay is allowed to see: routing data and opaque ciphertext."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=8, max_length=64)
    sender: str = Field(min_length=1, max_length=64)
    recipient: str = Field(min_length=1, max_length=64)
    mode: Literal["otp-wc", "aes-gcm"]
    seq: int = Field(ge=0)
    key_ids: list[str] = Field(min_length=1, max_length=4)
    ciphertext: str = Field(max_length=200_000)  # base64
    tag: str | None = Field(None, max_length=64)  # hex, mode dependent
    nonce: str | None = Field(None, max_length=64)
    aad: str | None = Field(None, max_length=2_000)
