from __future__ import annotations

import builtins
import os
from pathlib import Path
from typing import IO, Any, Protocol
from urllib import request

from .decisions import Decision
from .emitter import EventEmitter
from .exceptions import FlowguardBlocked
from .provenance import SECRET_LABEL, Provenance, SourceRef
from .tracked import provenance_of, track_value
from .tools import FlowguardTool

_REAL_OPEN = builtins.open


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

    def protect(self) -> Any:
        from .protect import ProtectionContext

        return ProtectionContext(self)

    def run_python(
        self,
        code: str,
        *,
        inputs: dict[str, Any] | None = None,
    ) -> Any:
        from .executor import run_python

        return run_python(self, code, inputs=inputs)

    def tool(
        self,
        func: Any | None = None,
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> Any:
        def decorate(wrapped: Any) -> FlowguardTool:
            return FlowguardTool(
                self,
                wrapped,
                name=name,
                description=description,
            )

        if func is None:
            return decorate
        return decorate(func)

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

    def block_unbrokered_subprocess(self, api: str) -> Decision:
        return Decision.block_unbrokered_subprocess(api)


class GuardedFile:
    def __init__(
        self,
        runtime: FlowguardRuntime,
        path: str | Path,
        mode: str = "r",
        **kwargs: Any,
    ) -> None:
        self._runtime = runtime
        self._path = Path(os.fsdecode(path))
        self._handle: IO[Any] = _REAL_OPEN(self._path, mode, **kwargs)

    def read(self, *args: Any, **kwargs: Any) -> Any:
        value = self._handle.read(*args, **kwargs)
        is_secret = self._runtime.is_secret_path(self._path)

        self._runtime.emitter.emit(
            "file_read",
            path=str(self._path),
            secret=is_secret,
            length=len(value),
        )

        if not is_secret:
            return value

        provenance = Provenance.from_source(
            label=SECRET_LABEL,
            source=SourceRef.file(self._path),
        )
        return track_value(value, provenance)

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> "GuardedFile":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)


class HttpTransport(Protocol):
    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> Any:
        ...


class UrllibHttpTransport:
    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        body = data.encode("utf-8") if isinstance(data, str) else data
        req = request.Request(url, data=body, method="POST", **kwargs)
        with request.urlopen(req) as response:
            return response.read()


class GuardedHttpClient:
    def __init__(
        self,
        runtime: FlowguardRuntime,
        transport: HttpTransport | None = None,
    ) -> None:
        self._runtime = runtime
        self._transport = transport or UrllibHttpTransport()

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> Any:
        provenance = provenance_of(data)

        self._runtime.emitter.emit(
            "http_send_attempt",
            url=url,
            labels=sorted(provenance.labels),
        )

        decision = self._runtime.check_network_egress(url, data)
        if decision is not None:
            self._runtime.emitter.emit(
                "http_send_blocked",
                url=url,
                policy=decision.policy,
                explanation=decision.explanation,
            )
            raise FlowguardBlocked(decision)

        self._runtime.emitter.emit("http_send_allowed", url=url)
        return self._transport.post(url, data=data, **kwargs)


def _normalize_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _is_child_path(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True
