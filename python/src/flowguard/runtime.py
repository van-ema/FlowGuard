from __future__ import annotations

import builtins
import os
from pathlib import Path
from typing import IO, Any, Protocol
from urllib import request

from .decisions import Decision
from .emitter import EventEmitter
from .exceptions import FlowguardBlocked
from .precision import PrecisionLoss, PrecisionMode, normalize_precision_mode
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
        precision_mode: str = "warn",
    ) -> None:
        self.secret_paths = tuple(_normalize_path(path) for path in secret_paths)
        self.emitter = EventEmitter(event_log)
        self.http = GuardedHttpClient(self, http_transport)
        self.precision_mode: PrecisionMode = normalize_precision_mode(precision_mode)
        self._scope_counter = 0
        self._scope_stack: list[str] = []
        self._precision_losses_by_scope: dict[str | None, list[PrecisionLoss]] = {}

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
        precision_loss = self.unresolved_precision_loss()
        if self.precision_mode == "strict" and precision_loss is not None:
            return Decision.block_taint_precision_lost_to_network(target, precision_loss)
        return None

    def block_unbrokered_subprocess(self, api: str) -> Decision:
        return Decision.block_unbrokered_subprocess(api)

    def begin_protection_scope(self) -> str:
        self._scope_counter += 1
        scope_id = f"scope-{self._scope_counter}"
        self._scope_stack.append(scope_id)
        return scope_id

    def end_protection_scope(self, scope_id: str) -> None:
        if self._scope_stack and self._scope_stack[-1] == scope_id:
            self._scope_stack.pop()
        elif scope_id in self._scope_stack:
            self._scope_stack.remove(scope_id)

    def current_scope_id(self) -> str | None:
        if not self._scope_stack:
            return None
        return self._scope_stack[-1]

    def record_precision_lost(
        self,
        *,
        operation: str,
        reason: str,
        provenance: Provenance,
        input_types: tuple[str, ...],
        output_type: str,
    ) -> PrecisionLoss | None:
        if not provenance.labels and not provenance.sources:
            return None

        loss = PrecisionLoss(
            operation=operation,
            reason=reason,
            provenance=provenance,
            input_types=input_types,
            output_type=output_type,
            scope_id=self.current_scope_id(),
        )
        self._precision_losses_by_scope.setdefault(loss.scope_id, []).append(loss)
        self.emitter.emit("taint_precision_lost", **loss.to_event_details())
        return loss

    def unresolved_precision_loss(self) -> PrecisionLoss | None:
        losses = self._precision_losses_by_scope.get(self.current_scope_id(), [])
        for loss in reversed(losses):
            if loss.provenance.has_label(SECRET_LABEL):
                return loss
        return None

    def report(self) -> "FlowguardReport":
        from .report import FlowguardReport

        return FlowguardReport.from_events(self.emitter.events)


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
            sources=_provenance_sources(provenance),
            transforms=_provenance_transforms(provenance),
            scope_id=self._runtime.current_scope_id(),
        )

        decision = self._runtime.check_network_egress(url, data)
        if decision is not None:
            decision_provenance = decision.provenance
            self._runtime.emitter.emit(
                "http_send_blocked",
                url=url,
                policy=decision.policy,
                explanation=decision.explanation,
                labels=sorted(decision_provenance.labels),
                sources=_provenance_sources(decision_provenance),
                transforms=_provenance_transforms(decision_provenance),
                precision_loss=_decision_precision_loss(decision),
                scope_id=self._runtime.current_scope_id(),
            )
            raise FlowguardBlocked(decision)

        self._runtime.emitter.emit(
            "http_send_allowed",
            url=url,
            labels=sorted(provenance.labels),
            sources=_provenance_sources(provenance),
            transforms=_provenance_transforms(provenance),
            scope_id=self._runtime.current_scope_id(),
        )
        return self._transport.post(url, data=data, **kwargs)


def _normalize_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _is_child_path(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _provenance_sources(provenance: Provenance) -> list[str]:
    return [source.display() for source in provenance.sources]


def _provenance_transforms(provenance: Provenance) -> list[dict[str, str]]:
    return [transform.to_dict() for transform in provenance.transforms]


def _decision_precision_loss(decision: Decision) -> object | None:
    if decision.context is None:
        return None
    return decision.context.get("precision_loss")
