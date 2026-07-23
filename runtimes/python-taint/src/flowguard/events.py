from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    event_type: str
    details: dict[str, Any]

