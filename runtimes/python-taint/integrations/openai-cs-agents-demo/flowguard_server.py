from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from flowguard import FlowguardRuntime
from server import AirlineServer


class FlowguardAirlineServer(AirlineServer):
    """Keep sidecar provenance isolated for each streamed ChatKit request."""

    def __init__(self, runtime: FlowguardRuntime) -> None:
        self.flowguard_runtime = runtime
        super().__init__()

    async def respond(
        self,
        thread: Any,
        input_user_message: Any,
        context: dict[str, Any],
    ) -> AsyncIterator[Any]:
        with self.flowguard_runtime.provenance_context.scope():
            async for event in super().respond(
                thread,
                input_user_message,
                context,
            ):
                yield event
