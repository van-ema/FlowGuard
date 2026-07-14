from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

SECRET_LABEL = "Secret"


@dataclass(frozen=True, slots=True)
class SourceRef:
    kind: str
    name: str

    @classmethod
    def file(cls, path: str | Path) -> "SourceRef":
        return cls(kind="file", name=str(path))

    def display(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass(frozen=True, slots=True)
class Provenance:
    labels: frozenset[str] = field(default_factory=frozenset)
    sources: tuple[SourceRef, ...] = field(default_factory=tuple)

    @classmethod
    def empty(cls) -> "Provenance":
        return cls()

    @classmethod
    def from_source(cls, label: str, source: SourceRef) -> "Provenance":
        return cls(labels=frozenset({label}), sources=(source,))

    def has_label(self, label: str) -> bool:
        return label in self.labels

    def merge(self, other: "Provenance") -> "Provenance":
        return Provenance(
            labels=self.labels | other.labels,
            sources=_dedupe_sources((*self.sources, *other.sources)),
        )


def merge_provenance(items: Iterable[Provenance]) -> Provenance:
    merged = Provenance.empty()
    for item in items:
        merged = merged.merge(item)
    return merged


def _dedupe_sources(sources: tuple[SourceRef, ...]) -> tuple[SourceRef, ...]:
    return tuple(dict.fromkeys(sources))

