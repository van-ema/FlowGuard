from __future__ import annotations

from typing import Any, Protocol
from urllib import request

from .exceptions import FlowguardBlocked
from .tracked import provenance_of


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
    def __init__(self, runtime: Any, transport: HttpTransport | None = None) -> None:
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

