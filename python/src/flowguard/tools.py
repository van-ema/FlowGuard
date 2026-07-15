from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .tracked import provenance_of


@dataclass(frozen=True, slots=True)
class ToolCallContext:
    name: str


class FlowguardTool:
    def __init__(
        self,
        runtime: Any,
        func: Callable[..., Any],
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> None:
        self._runtime = runtime
        self._func = func
        self.name = name or func.__name__
        self.description = description or func.__doc__

    @property
    def function(self) -> Callable[..., Any]:
        return self._func

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        context = ToolCallContext(name=self.name)
        self._runtime.emitter.emit(
            "tool_start",
            name=context.name,
            positional_arg_count=len(args),
            keyword_names=sorted(kwargs),
        )

        try:
            result = self._func(*args, **kwargs)
        except Exception as err:
            self._runtime.emitter.emit(
                "tool_error",
                name=context.name,
                error_type=type(err).__name__,
            )
            raise

        provenance = provenance_of(result)
        self._runtime.emitter.emit(
            "tool_end",
            name=context.name,
            result_labels=sorted(provenance.labels),
        )
        return result

    def as_openai_tool(self) -> Any:
        from .adapters.openai_agents import as_openai_tool

        return as_openai_tool(self)

