"""Authentication key pool: the pre-shared secret that makes QKD "key growing".

Alice and Bob start with the same pre-shared secret (in reality exchanged in
person or by a trusted courier). Every session *burns* a fixed budget from the
front of the pool, success or abort, so both copies stay in lock-step and no
pad is ever used twice; a successful session pays it back from fresh key.
An adversary who forces aborts can therefore drain the pool, which is the
denial-of-service limitation discussed in docs/security-model.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class AuthKeyExhausted(Exception):
    pass


@dataclass
class AuthKeyPool:
    material: bytearray = field(default_factory=bytearray)
    consumed: int = 0  # bytes burned so far (for display)
    replenished: int = 0

    @classmethod
    def from_preshared(cls, secret: bytes) -> AuthKeyPool:
        return cls(bytearray(secret))

    @property
    def available(self) -> int:
        return len(self.material)

    def take(self, n_bytes: int) -> bytes:
        if n_bytes > len(self.material):
            raise AuthKeyExhausted(
                f"need {n_bytes} bytes of authentication key, {len(self.material)} left; "
                "the link must be re-provisioned with a new pre-shared secret"
            )
        out = bytes(self.material[:n_bytes])
        del self.material[:n_bytes]
        self.consumed += n_bytes
        return out

    def replenish(self, fresh: bytes) -> None:
        self.material.extend(fresh)
        self.replenished += len(fresh)
