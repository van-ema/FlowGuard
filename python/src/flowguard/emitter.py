from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class EventEmitter:
    def __init__(self, event_log: str | Path | None = None) -> None:
        self._event_log = Path(event_log) if event_log is not None else None
        self.events: list[dict[str, Any]] = []

    def emit(self, event_type: str, **details: Any) -> dict[str, Any]:
        record = {
            "sequence": len(self.events),
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

