from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .provenance import Provenance

PrecisionMode = Literal["warn", "strict"]


@dataclass(frozen=True, slots=True)
class PrecisionLoss:
    operation: str
    reason: str
    provenance: Provenance
    input_types: tuple[str, ...]
    output_type: str
    scope_id: str | None

    def to_event_details(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "reason": self.reason,
            "labels": sorted(self.provenance.labels),
            "sources": [source.display() for source in self.provenance.sources],
            "transforms": [
                transform.to_dict() for transform in self.provenance.transforms
            ],
            "input_types": list(self.input_types),
            "output_type": self.output_type,
            "scope_id": self.scope_id,
        }


def normalize_precision_mode(mode: str) -> PrecisionMode:
    if mode == "warn":
        return "warn"
    if mode == "strict":
        return "strict"
    raise ValueError("precision_mode must be 'warn' or 'strict'")
