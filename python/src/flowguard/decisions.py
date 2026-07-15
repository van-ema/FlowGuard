from __future__ import annotations

from dataclasses import dataclass

from .provenance import Provenance


@dataclass(frozen=True, slots=True)
class Decision:
    kind: str
    policy: str
    target: str
    explanation: str
    provenance: Provenance

    @classmethod
    def block_secret_to_network(cls, target: str, provenance: Provenance) -> "Decision":
        sources = ", ".join(source.display() for source in provenance.sources)
        return cls(
            kind="Block",
            policy="SecretToNetwork",
            target=target,
            explanation=f"Secret-derived payload from {sources} reached network sink {target}",
            provenance=provenance,
        )

