from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EventEmitter:
    def __init__(self, event_log: str | Path | None = None) -> None:
        self._event_log = Path(event_log) if event_log is not None else None
        self.events: list[dict[str, Any]] = []

    def emit(self, event_type: str, **details: Any) -> dict[str, Any]:
        record = {
            "sequence": len(self.events),
            "timestamp": _utc_now(),
            "type": event_type,
            "details": details,
        }
        self.events.append(record)

        if self._event_log is not None:
            self._event_log.parent.mkdir(parents=True, exist_ok=True)
            with self._event_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True))
                handle.write("\n")

        return record


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00",
        "Z",
    )
