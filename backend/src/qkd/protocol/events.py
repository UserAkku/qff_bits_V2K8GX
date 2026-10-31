"""Progress events the protocol emits for the live key-establishment view."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Event:
    stage: str  # quantum | sifting | estimation | reconciliation | verification | amplification | authentication | result
    kind: str  # what happened within the stage
    data: dict[str, Any] = field(default_factory=dict)
    t: float = field(default_factory=time.time)


Emit = Callable[[Event], None]


def null_emit(_: Event) -> None:
    return None


class Recorder:
    """Collects events (tests, experiments, replay for late-joining viewers)."""

    def __init__(self, forward: Emit | None = None):
        self.events: list[Event] = []
        self._forward = forward

    def __call__(self, event: Event) -> None:
        self.events.append(event)
        if self._forward:
            self._forward(event)

    def of(self, stage: str, kind: str | None = None) -> list[Event]:
        return [e for e in self.events if e.stage == stage and (kind is None or e.kind == kind)]
