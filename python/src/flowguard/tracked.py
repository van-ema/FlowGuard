from __future__ import annotations

from typing import Any

from .provenance import Provenance, merge_provenance


class TrackedStr(str):
    def __new__(cls, value: str, provenance: Provenance) -> "TrackedStr":
        obj = str.__new__(cls, value)
        obj.provenance = provenance
        return obj

    def __add__(self, other: object) -> "TrackedStr":
        value = str.__add__(self, str(other))
        return TrackedStr(value, provenance_of(self).merge(provenance_of(other)))

    def __radd__(self, other: object) -> "TrackedStr":
        value = str.__add__(str(other), self)
        return TrackedStr(value, provenance_of(other).merge(provenance_of(self)))

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> "TrackedBytes":
        return TrackedBytes(super().encode(encoding, errors), provenance_of(self))


class TrackedBytes(bytes):
    def __new__(cls, value: bytes, provenance: Provenance) -> "TrackedBytes":
        obj = bytes.__new__(cls, value)
        obj.provenance = provenance
        return obj

    def __add__(self, other: object) -> "TrackedBytes":
        value = bytes.__add__(self, bytes(other))
        return TrackedBytes(value, provenance_of(self).merge(provenance_of(other)))

    def __radd__(self, other: object) -> "TrackedBytes":
        value = bytes.__add__(bytes(other), self)
        return TrackedBytes(value, provenance_of(other).merge(provenance_of(self)))

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> TrackedStr:
        return TrackedStr(super().decode(encoding, errors), provenance_of(self))


def track_value(value: Any, provenance: Provenance) -> Any:
    if isinstance(value, str):
        return TrackedStr(value, provenance)
    if isinstance(value, bytes):
        return TrackedBytes(value, provenance)
    return value


def provenance_of(value: Any) -> Provenance:
    if isinstance(value, (TrackedStr, TrackedBytes)):
        return value.provenance
    if isinstance(value, dict):
        return merge_provenance(provenance_of(item) for pair in value.items() for item in pair)
    if isinstance(value, (list, tuple, set, frozenset)):
        return merge_provenance(provenance_of(item) for item in value)
    return Provenance.empty()

