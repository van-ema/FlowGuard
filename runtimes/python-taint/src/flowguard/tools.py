from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .provenance import Provenance, SourceRef
from .tracked import provenance_of


@dataclass(frozen=True, slots=True)
class ToolCallContext:
    name: str


@dataclass(frozen=True, slots=True, init=False)
class ToolSourceRule:
    """Provenance introduced by an existing tool's output."""

    tool_name: str
    labels: frozenset[str]
    source: SourceRef

    def __init__(
        self,
        tool_name: str,
        *,
        labels: Iterable[str],
        source: SourceRef,
    ) -> None:
        normalized_labels = frozenset(labels)
        if not tool_name:
            raise ValueError("tool source rule requires a tool name")
        if not normalized_labels:
            raise ValueError("tool source rule requires at least one label")
        object.__setattr__(self, "tool_name", tool_name)
        object.__setattr__(self, "labels", normalized_labels)
        object.__setattr__(self, "source", source)

    @property
    def provenance(self) -> Provenance:
        return Provenance(labels=self.labels, sources=(self.source,))


@dataclass(frozen=True, slots=True, init=False)
class ToolSinkRule:
    """Block a tool call when its provenance contains a selected label.

    This is an enforcement rule, not a propagation rule. Any overlap between
    ``labels`` and the call's provenance labels is a policy violation, and the
    tool callback is not executed.
    """

    tool_name: str
    labels: frozenset[str]
    policy: str
    target: str

    def __init__(
        self,
        tool_name: str,
        *,
        labels: Iterable[str],
        policy: str = "SensitiveToTool",
        target: str | None = None,
    ) -> None:
        normalized_labels = frozenset(labels)
        if not tool_name:
            raise ValueError("tool sink rule requires a tool name")
        if not normalized_labels:
            raise ValueError("tool sink rule requires at least one label")
        if not policy:
            raise ValueError("tool sink rule requires a policy name")
        object.__setattr__(self, "tool_name", tool_name)
        object.__setattr__(self, "labels", normalized_labels)
        object.__setattr__(self, "policy", policy)
        object.__setattr__(self, "target", target or f"tool:{tool_name}")

    def matches(self, provenance: Provenance) -> bool:
        """Return true when at least one forbidden label reaches this sink."""

        return bool(self.labels & provenance.labels)


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

    @property
    def runtime(self) -> Any:
        return self._runtime

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        context = ToolCallContext(name=self.name)
        args, kwargs = self._runtime.provenance_context.prepare_tool_arguments(
            args,
            kwargs,
        )
        self._runtime.emitter.emit(
            "tool_start",
            name=context.name,
            positional_arg_count=len(args),
            keyword_names=sorted(kwargs),
        )

        try:
            with self._runtime.protect():
                result = self._func(*args, **kwargs)
        except Exception as err:
            self._runtime.emitter.emit(
                "tool_error",
                name=context.name,
                error_type=type(err).__name__,
            )
            raise

        provenance = provenance_of(result)
        self._runtime.provenance_context.bind_active_tool_output(provenance)
        self._runtime.emitter.emit(
            "tool_end",
            name=context.name,
            result_labels=sorted(provenance.labels),
        )
        return result

    def as_openai_tool(self) -> Any:
        try:
            from .adapters.openai_agents import as_openai_tool
        except ModuleNotFoundError as err:
            if err.name != "agents":
                raise
            raise RuntimeError(
                "OpenAI Agents SDK is not installed. Install openai-agents "
                "before calling as_openai_tool()."
            ) from err

        return as_openai_tool(self)

    def as_langchain_tool(self) -> Any:
        """Return a LangChain tool that keeps Flowguard protection active."""

        from .adapters.langchain import as_langchain_tool

        return as_langchain_tool(self)
