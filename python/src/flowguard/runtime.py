from __future__ import annotations

from pathlib import Path
from typing import Any

from .decisions import Decision
from .emitter import EventEmitter
from .files import GuardedFile
from .http import GuardedHttpClient, HttpTransport
from .provenance import SECRET_LABEL
from .tracked import provenance_of


class FlowguardRuntime:
    """Facade for guarded Python IO boundaries and taint-policy checks."""

    def __init__(
        self,
        *,
        secret_paths: list[str | Path] | tuple[str | Path, ...] = (),
        event_log: str | Path | None = None,
        http_transport: HttpTransport | None = None,
    ) -> None:
        self.secret_paths = tuple(_normalize_path(path) for path in secret_paths)
        self.emitter = EventEmitter(event_log)
        self.http = GuardedHttpClient(self, http_transport)

    def open(self, path: str | Path, mode: str = "r", **kwargs: Any) -> GuardedFile:
        return GuardedFile(self, path, mode, **kwargs)

    def is_secret_path(self, path: str | Path) -> bool:
        candidate = _normalize_path(path)
        for secret in self.secret_paths:
            if candidate == secret or _is_child_path(candidate, secret):
                return True
        return False

    def check_network_egress(self, target: str, payload: Any) -> Decision | None:
        provenance = provenance_of(payload)
        if provenance.has_label(SECRET_LABEL):
            return Decision.block_secret_to_network(target, provenance)
        return None


def _normalize_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _is_child_path(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True

