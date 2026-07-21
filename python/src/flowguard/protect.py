from __future__ import annotations

import builtins
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib import request as urllib_request

from .exceptions import FlowguardBlocked
from .tracked import provenance_of


@dataclass(frozen=True, slots=True)
class _Patch:
    target: Any
    name: str
    original: Any


class ProtectionContext:
    def __init__(self, runtime: Any) -> None:
        self._runtime = runtime
        self._patches: list[_Patch] = []
        self._scope_id: str | None = None

    def __enter__(self) -> "ProtectionContext":
        self._scope_id = self._runtime.begin_protection_scope()
        self._runtime.emitter.emit("protect_start", scope_id=self._scope_id)
        self._patch(builtins, "open", self._guarded_open(builtins.open))
        self._patch_http_clients()
        self._patch_subprocess()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        for patch in reversed(self._patches):
            setattr(patch.target, patch.name, patch.original)
        self._patches.clear()
        self._runtime.emitter.emit("protect_end", scope_id=self._scope_id)
        if self._scope_id is not None:
            self._runtime.end_protection_scope(self._scope_id)
            self._scope_id = None
        return False

    def _patch(self, target: Any, name: str, replacement: Any) -> None:
        original = getattr(target, name, None)
        if original is None:
            return
        self._patches.append(_Patch(target=target, name=name, original=original))
        setattr(target, name, replacement)

    def _guarded_open(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(
            file: Any,
            mode: str = "r",
            buffering: int = -1,
            encoding: str | None = None,
            errors: str | None = None,
            newline: str | None = None,
            closefd: bool = True,
            opener: Callable[..., Any] | None = None,
        ) -> Any:
            if not isinstance(file, (str, bytes, os.PathLike)):
                return original(
                    file,
                    mode,
                    buffering,
                    encoding,
                    errors,
                    newline,
                    closefd,
                    opener,
                )

            return self._runtime.open(
                file,
                mode,
                buffering=buffering,
                encoding=encoding,
                errors=errors,
                newline=newline,
                closefd=closefd,
                opener=opener,
            )

        return wrapper

    def _patch_http_clients(self) -> None:
        self._patch(urllib_request, "urlopen", self._guarded_urlopen(urllib_request.urlopen))

        requests_module = sys.modules.get("requests")
        if requests_module is not None:
            self._patch_optional_http_post(requests_module, "requests.post")
            self._patch_optional_http_request(requests_module, "requests.request")

        httpx_module = sys.modules.get("httpx")
        if httpx_module is not None:
            self._patch_optional_http_post(httpx_module, "httpx.post")
            self._patch_optional_http_request(httpx_module, "httpx.request")

    def _patch_optional_http_post(self, module: Any, api: str) -> None:
        original = getattr(module, "post", None)
        if original is not None:
            self._patch(module, "post", self._guarded_http_post(original, api))

    def _patch_optional_http_request(self, module: Any, api: str) -> None:
        original = getattr(module, "request", None)
        if original is not None:
            self._patch(module, "request", self._guarded_http_request(original, api))

    def _guarded_http_post(
        self,
        original: Callable[..., Any],
        api: str,
    ) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            target = args[0] if args else kwargs.get("url", "")
            payloads = [
                args[1] if len(args) > 1 else None,
                kwargs.get("data"),
                kwargs.get("json"),
            ]
            self._check_network_egress(str(target), payloads, api)
            return original(*args, **kwargs)

        return wrapper

    def _guarded_http_request(
        self,
        original: Callable[..., Any],
        api: str,
    ) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            target = args[1] if len(args) > 1 else kwargs.get("url", "")
            payloads = [kwargs.get("data"), kwargs.get("json")]
            self._check_network_egress(str(target), payloads, api)
            return original(*args, **kwargs)

        return wrapper

    def _guarded_urlopen(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(url: Any, data: Any = None, *args: Any, **kwargs: Any) -> Any:
            target = getattr(url, "full_url", url)
            request_data = getattr(url, "data", None)
            self._check_network_egress(
                str(target),
                [data, request_data],
                "urllib.request.urlopen",
            )
            return original(url, data, *args, **kwargs)

        return wrapper

    def _check_network_egress(self, target: str, payload: Any, api: str) -> None:
        provenance = provenance_of(payload)
        self._runtime.emitter.emit(
            "http_send_attempt",
            url=target,
            labels=sorted(provenance.labels),
            sources=[source.display() for source in provenance.sources],
            transforms=[transform.to_dict() for transform in provenance.transforms],
            api=api,
            scope_id=self._runtime.current_scope_id(),
        )

        decision = self._runtime.check_network_egress(target, payload)
        if decision is not None:
            decision_provenance = decision.provenance
            self._runtime.emitter.emit(
                "http_send_blocked",
                url=target,
                policy=decision.policy,
                explanation=decision.explanation,
                labels=sorted(decision_provenance.labels),
                sources=[
                    source.display() for source in decision_provenance.sources
                ],
                transforms=[
                    transform.to_dict()
                    for transform in decision_provenance.transforms
                ],
                precision_loss=_decision_precision_loss(decision),
                api=api,
                scope_id=self._runtime.current_scope_id(),
            )
            raise FlowguardBlocked(decision)

        self._runtime.emitter.emit(
            "http_send_allowed",
            url=target,
            labels=sorted(provenance.labels),
            sources=[source.display() for source in provenance.sources],
            transforms=[transform.to_dict() for transform in provenance.transforms],
            api=api,
            scope_id=self._runtime.current_scope_id(),
        )

    def _patch_subprocess(self) -> None:
        for name in ("Popen", "run", "call", "check_call", "check_output"):
            self._patch(subprocess, name, self._blocked_subprocess(f"subprocess.{name}"))

    def _blocked_subprocess(self, api: str) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            decision = self._runtime.block_unbrokered_subprocess(api)
            self._runtime.emitter.emit(
                "subprocess_blocked",
                api=api,
                policy=decision.policy,
                explanation=decision.explanation,
            )
            raise FlowguardBlocked(decision)

        return wrapper


def _decision_precision_loss(decision: Any) -> object | None:
    context = getattr(decision, "context", None)
    if context is None:
        return None
    return context.get("precision_loss")
