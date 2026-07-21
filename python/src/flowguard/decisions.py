from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .precision import PrecisionLoss
from .provenance import Provenance


@dataclass(frozen=True, slots=True)
class Decision:
    """Policy outcome returned before a guarded action is allowed to continue."""

    kind: str
    policy: str
    target: str
    explanation: str
    provenance: Provenance
    context: dict[str, Any] | None = None

    @classmethod
    def block_secret_to_network(cls, target: str, provenance: Provenance) -> "Decision":
        """Blocks a network sink whose payload still carries secret provenance."""

        sources = ", ".join(source.display() for source in provenance.sources)
        return cls(
            kind="Block",
            policy="SecretToNetwork",
            target=target,
            explanation=f"Secret-derived payload from {sources} reached network sink {target}",
            provenance=provenance,
        )

    @classmethod
    def block_unbrokered_subprocess(cls, api: str) -> "Decision":
        """Blocks subprocess APIs that run inside protect() without a broker."""

        return cls(
            kind="Block",
            policy="UnbrokeredSubprocess",
            target=api,
            explanation=(
                f"Subprocess execution through {api} is blocked inside "
                "Flowguard protect(); use a brokered subprocess boundary."
            ),
            provenance=Provenance.empty(),
        )

    @classmethod
    def block_taint_precision_lost_to_network(
        cls,
        target: str,
        precision_loss: PrecisionLoss,
    ) -> "Decision":
        """Blocks target after secret provenance was lost before network egress.

        target is the sink identifier Flowguard is about to allow, normally a URL
        or endpoint string from the guarded HTTP call.
        """

        sources = ", ".join(
            source.display() for source in precision_loss.provenance.sources
        )
        return cls(
            kind="Block",
            policy="TaintPrecisionLostToNetwork",
            target=target,
            explanation=(
                f"Secret-derived data from {sources} crossed unsupported "
                f"transformation {precision_loss.operation}; strict mode blocked "
                f"network sink {target}"
            ),
            provenance=precision_loss.provenance,
            context={"precision_loss": precision_loss.to_event_details()},
        )
