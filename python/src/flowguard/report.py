from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

REPORT_SCHEMA_VERSION = "flowguard.report.v1"
BLOCKED_EVENT_TYPES = frozenset({"http_send_blocked", "subprocess_blocked"})


@dataclass(frozen=True, slots=True)
class ReportSummary:
    event_count: int
    violation_count: int
    blocked_count: int
    allowed_send_count: int


@dataclass(frozen=True, slots=True)
class ReportViolation:
    sequence: int
    event_type: str
    timestamp: str | None
    policy: str
    target: str
    explanation: str
    labels: list[str]
    sources: list[str]
    transforms: list[dict[str, str]]
    api: str | None = None


@dataclass(frozen=True, slots=True)
class ReportNetworkSend:
    sequence: int
    timestamp: str | None
    target: str
    api: str | None
    labels: list[str]
    sources: list[str]
    transforms: list[dict[str, str]]


@dataclass(frozen=True, slots=True)
class FlowguardReport:
    """Structured view over runtime events for audit and demos."""

    schema_version: str
    summary: ReportSummary
    violations: list[ReportViolation]
    allowed_sends: list[ReportNetworkSend]
    events: list[dict[str, Any]]

    @classmethod
    def from_events(cls, events: Iterable[dict[str, Any]]) -> "FlowguardReport":
        copied_events = [_copy_event(event) for event in events]
        violations = [
            _violation_from_event(event)
            for event in copied_events
            if event.get("type") in BLOCKED_EVENT_TYPES
        ]
        allowed_sends = [
            _allowed_send_from_event(event)
            for event in copied_events
            if event.get("type") == "http_send_allowed"
        ]
        summary = ReportSummary(
            event_count=len(copied_events),
            violation_count=len(violations),
            blocked_count=len(violations),
            allowed_send_count=len(allowed_sends),
        )
        return cls(
            schema_version=REPORT_SCHEMA_VERSION,
            summary=summary,
            violations=violations,
            allowed_sends=allowed_sends,
            events=copied_events,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "summary": asdict(self.summary),
            "violations": [asdict(violation) for violation in self.violations],
            "allowed_sends": [asdict(send) for send in self.allowed_sends],
            "events": self.events,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, default=str)

    def write_json(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(f"{self.to_json()}\n", encoding="utf-8")

    def write_jsonl(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(event, sort_keys=True, default=str))
                handle.write("\n")


def _copy_event(event: dict[str, Any]) -> dict[str, Any]:
    copied = dict(event)
    details = copied.get("details")
    if isinstance(details, dict):
        copied["details"] = dict(details)
    return copied


def _violation_from_event(event: dict[str, Any]) -> ReportViolation:
    details = _details(event)
    return ReportViolation(
        sequence=_sequence(event),
        event_type=str(event.get("type", "")),
        timestamp=_timestamp(event),
        policy=str(details.get("policy", "")),
        target=_target(details),
        explanation=str(details.get("explanation", "")),
        labels=_string_list(details.get("labels")),
        sources=_string_list(details.get("sources")),
        transforms=_transform_list(details.get("transforms")),
        api=_optional_string(details.get("api")),
    )


def _allowed_send_from_event(event: dict[str, Any]) -> ReportNetworkSend:
    details = _details(event)
    return ReportNetworkSend(
        sequence=_sequence(event),
        timestamp=_timestamp(event),
        target=_target(details),
        api=_optional_string(details.get("api")),
        labels=_string_list(details.get("labels")),
        sources=_string_list(details.get("sources")),
        transforms=_transform_list(details.get("transforms")),
    )


def _details(event: dict[str, Any]) -> dict[str, Any]:
    details = event.get("details")
    if isinstance(details, dict):
        return details
    return {}


def _sequence(event: dict[str, Any]) -> int:
    sequence = event.get("sequence")
    if isinstance(sequence, int):
        return sequence
    return 0


def _timestamp(event: dict[str, Any]) -> str | None:
    timestamp = event.get("timestamp")
    if timestamp is None:
        return None
    return str(timestamp)


def _target(details: dict[str, Any]) -> str:
    if "url" in details:
        return str(details["url"])
    if "target" in details:
        return str(details["target"])
    if "api" in details:
        return str(details["api"])
    return ""


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(item) for item in value]
    return [str(value)]


def _transform_list(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, (list, tuple)):
        return []
    transforms: list[dict[str, str]] = []
    for item in value:
        if isinstance(item, dict):
            transforms.append(
                {
                    "operation": str(item.get("operation", "")),
                    "input_type": str(item.get("input_type", "")),
                    "output_type": str(item.get("output_type", "")),
                }
            )
    return transforms
