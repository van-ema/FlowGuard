from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatchcase
from typing import Iterable

from .provenance import SECRET_LABEL, Provenance


class ModelEgressAction(str, Enum):
    """Action taken before data crosses a model-provider boundary."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ALLOW_AND_PROPAGATE = "ALLOW_AND_PROPAGATE"


@dataclass(frozen=True, slots=True)
class ModelDestination:
    """Trusted policy identity for a configured model endpoint."""

    provider: str
    model: str
    trust_zone: str = "external"

    @property
    def target(self) -> str:
        return f"model:{self.provider}:{self.model}:{self.trust_zone}"


@dataclass(frozen=True, slots=True)
class ModelRule:
    """A label and destination match that selects a model-egress action."""

    labels: frozenset[str]
    destinations: tuple[str, ...]
    action: ModelEgressAction
    policy: str

    @classmethod
    def block(
        cls,
        *,
        labels: Iterable[str],
        destinations: Iterable[str],
        policy: str = "SensitiveToModel",
    ) -> "ModelRule":
        return cls(
            labels=frozenset(labels),
            destinations=tuple(destinations),
            action=ModelEgressAction.BLOCK,
            policy=policy,
        )

    @classmethod
    def allow_and_propagate(
        cls,
        *,
        labels: Iterable[str],
        destinations: Iterable[str],
        policy: str = "ApprovedSensitiveToModel",
    ) -> "ModelRule":
        return cls(
            labels=frozenset(labels),
            destinations=tuple(destinations),
            action=ModelEgressAction.ALLOW_AND_PROPAGATE,
            policy=policy,
        )

    def matches(self, destination: ModelDestination, provenance: Provenance) -> bool:
        if self.action is ModelEgressAction.ALLOW_AND_PROPAGATE:
            labels_match = bool(provenance.labels) and provenance.labels <= self.labels
        else:
            labels_match = bool(self.labels & provenance.labels)
        return labels_match and any(
            fnmatchcase(destination.target, pattern) for pattern in self.destinations
        )


@dataclass(frozen=True, slots=True)
class ModelPolicyResult:
    action: ModelEgressAction
    policy: str


@dataclass(frozen=True, slots=True)
class ModelEgressPolicy:
    """Ordered model rules with default-deny behavior for labeled data."""

    rules: tuple[ModelRule, ...] = ()

    def __init__(self, rules: Iterable[ModelRule] = ()) -> None:
        object.__setattr__(self, "rules", tuple(rules))

    def evaluate(
        self,
        destination: ModelDestination,
        provenance: Provenance,
    ) -> ModelPolicyResult:
        if not provenance.labels:
            return ModelPolicyResult(
                action=ModelEgressAction.ALLOW,
                policy="PublicToModel",
            )

        for rule in self.rules:
            if rule.matches(destination, provenance):
                return ModelPolicyResult(action=rule.action, policy=rule.policy)

        policy = (
            "SecretToModel"
            if provenance.has_label(SECRET_LABEL)
            else "SensitiveToModel"
        )
        return ModelPolicyResult(
            action=ModelEgressAction.BLOCK,
            policy=policy,
        )
