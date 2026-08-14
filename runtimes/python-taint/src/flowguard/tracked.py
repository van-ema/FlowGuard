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
        provenance = provenance_of(self).merge(provenance_of(other))
        return TrackedStr(
            value,
            _with_transform(provenance, "str.concat", "str", "str"),
        )

    def __radd__(self, other: object) -> "TrackedStr":
        value = str.__add__(str(other), self)
        provenance = provenance_of(other).merge(provenance_of(self))
        return TrackedStr(
            value,
            _with_transform(provenance, "str.concat", "str", "str"),
        )

    def __getitem__(self, key: Any) -> "TrackedStr":
        provenance = _with_transform(provenance_of(self), "str.slice", "str", "str")
        return TrackedStr(super().__getitem__(key), provenance)

    def __format__(self, format_spec: str) -> "TrackedStr":
        provenance = _with_transform(provenance_of(self), "str.format", "str", "str")
        return TrackedStr(super().__format__(format_spec), provenance)

    def __str__(self) -> "TrackedStr":
        return self

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> "TrackedBytes":
        provenance = _with_transform(provenance_of(self), "str.encode", "str", "bytes")
        return TrackedBytes(super().encode(encoding, errors), provenance)

    def lower(self) -> "TrackedStr":
        provenance = _with_transform(provenance_of(self), "str.lower", "str", "str")
        return TrackedStr(super().lower(), provenance)

    def upper(self) -> "TrackedStr":
        provenance = _with_transform(provenance_of(self), "str.upper", "str", "str")
        return TrackedStr(super().upper(), provenance)

    def strip(self, chars: str | None = None) -> "TrackedStr":
        provenance = _with_transform(provenance_of(self), "str.strip", "str", "str")
        return TrackedStr(super().strip(chars), provenance)

    def lstrip(self, chars: str | None = None) -> "TrackedStr":
        provenance = _with_transform(provenance_of(self), "str.lstrip", "str", "str")
        return TrackedStr(super().lstrip(chars), provenance)

    def rstrip(self, chars: str | None = None) -> "TrackedStr":
        provenance = _with_transform(provenance_of(self), "str.rstrip", "str", "str")
        return TrackedStr(super().rstrip(chars), provenance)

    def replace(self, old: str, new: str, count: int = -1) -> "TrackedStr":
        provenance = provenance_of(self).merge(provenance_of(old)).merge(provenance_of(new))
        return TrackedStr(
            super().replace(old, new, count),
            _with_transform(provenance, "str.replace", "str", "str"),
        )


class TrackedBytes(bytes):
    def __new__(cls, value: bytes, provenance: Provenance) -> "TrackedBytes":
        obj = bytes.__new__(cls, value)
        obj.provenance = provenance
        return obj

    def __add__(self, other: object) -> "TrackedBytes":
        value = bytes.__add__(self, bytes(other))
        provenance = provenance_of(self).merge(provenance_of(other))
        return TrackedBytes(
            value,
            _with_transform(provenance, "bytes.concat", "bytes", "bytes"),
        )

    def __radd__(self, other: object) -> "TrackedBytes":
        value = bytes.__add__(bytes(other), self)
        provenance = provenance_of(other).merge(provenance_of(self))
        return TrackedBytes(
            value,
            _with_transform(provenance, "bytes.concat", "bytes", "bytes"),
        )

    def __getitem__(self, key: Any) -> Any:
        value = super().__getitem__(key)
        if isinstance(value, bytes):
            provenance = _with_transform(provenance_of(self), "bytes.slice", "bytes", "bytes")
            return TrackedBytes(value, provenance)
        return value

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> TrackedStr:
        provenance = _with_transform(provenance_of(self), "bytes.decode", "bytes", "str")
        return TrackedStr(super().decode(encoding, errors), provenance)

    def lower(self) -> "TrackedBytes":
        provenance = _with_transform(provenance_of(self), "bytes.lower", "bytes", "bytes")
        return TrackedBytes(super().lower(), provenance)

    def upper(self) -> "TrackedBytes":
        provenance = _with_transform(provenance_of(self), "bytes.upper", "bytes", "bytes")
        return TrackedBytes(super().upper(), provenance)

    def strip(self, bytes_: bytes | None = None) -> "TrackedBytes":
        provenance = _with_transform(provenance_of(self), "bytes.strip", "bytes", "bytes")
        return TrackedBytes(super().strip(bytes_), provenance)

    def replace(self, old: bytes, new: bytes, count: int = -1) -> "TrackedBytes":
        provenance = provenance_of(self).merge(provenance_of(old)).merge(provenance_of(new))
        return TrackedBytes(
            super().replace(old, new, count),
            _with_transform(provenance, "bytes.replace", "bytes", "bytes"),
        )


def track_value(value: Any, provenance: Provenance) -> Any:
    if isinstance(value, str):
        return TrackedStr(value, provenance)
    if isinstance(value, bytes):
        return TrackedBytes(value, provenance)
    return value


def track_with_provenance(value: Any, provenance: Provenance) -> Any:
    """Apply provenance recursively after a framework serialization boundary."""

    merged = provenance_of(value).merge(provenance)
    if isinstance(value, str):
        return TrackedStr(value, merged)
    if isinstance(value, bytes):
        return TrackedBytes(value, merged)
    if isinstance(value, dict):
        return {
            key: track_with_provenance(item, provenance)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [track_with_provenance(item, provenance) for item in value]
    if isinstance(value, tuple):
        return tuple(track_with_provenance(item, provenance) for item in value)
    if isinstance(value, set):
        return {track_with_provenance(item, provenance) for item in value}
    if isinstance(value, frozenset):
        return frozenset(track_with_provenance(item, provenance) for item in value)
    return value


def untrack_value(value: Any) -> Any:
    """Return transport-safe base values after provenance is stored sidecar."""

    if isinstance(value, TrackedStr):
        return str.__str__(value)
    if isinstance(value, TrackedBytes):
        return bytes.__new__(bytes, value)
    if isinstance(value, dict):
        return {
            untrack_value(key): untrack_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [untrack_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(untrack_value(item) for item in value)
    if isinstance(value, set):
        return {untrack_value(item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(untrack_value(item) for item in value)
    return value


def provenance_of(value: Any) -> Provenance:
    if isinstance(value, (TrackedStr, TrackedBytes)):
        return value.provenance
    if isinstance(value, dict):
        return merge_provenance(provenance_of(item) for pair in value.items() for item in pair)
    if isinstance(value, (list, tuple, set, frozenset)):
        return merge_provenance(provenance_of(item) for item in value)
    return Provenance.empty()


def _with_transform(
    provenance: Provenance,
    operation: str,
    input_type: str,
    output_type: str,
) -> Provenance:
    return provenance.with_transform(
        operation=operation,
        input_type=input_type,
        output_type=output_type,
    )
