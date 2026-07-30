from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from .provenance import Provenance, merge_provenance
from .tracked import provenance_of, track_with_provenance

_TOOL_OUTPUT_TYPES = frozenset(
    {
        "function_call_output",
        "tool_call_output",
        "tool_result",
    }
)


@dataclass(frozen=True, slots=True)
class ModelInputProvenance:
    provenance: Provenance
    unknown_context_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ModelBinding:
    response_id: str | None
    tool_call_ids: tuple[str, ...]


@dataclass(slots=True)
class _RegistryState:
    # Child asyncio tasks inherit this object and publish bindings into the same
    # run registry. scope() gives concurrent agent runs different objects.
    tool_outputs: dict[str, Provenance] = field(default_factory=dict)
    model_responses: dict[str, Provenance] = field(default_factory=dict)
    generated_tool_calls: dict[str, Provenance] = field(default_factory=dict)
    conversations: dict[str, Provenance] = field(default_factory=dict)


class ProvenanceContext:
    """Async-safe sidecar provenance for serialized agent-framework values."""

    def __init__(self) -> None:
        suffix = id(self)
        self._state_var: ContextVar[_RegistryState] = ContextVar(
            f"flowguard_provenance_state_{suffix}",
            default=_RegistryState(),
        )
        self._active_tool_call_var: ContextVar[str | None] = ContextVar(
            f"flowguard_active_tool_call_{suffix}",
            default=None,
        )

    @contextmanager
    def scope(self) -> Iterator["ProvenanceContext"]:
        """Start an isolated run and release all bindings when it ends."""

        state_token = self._state_var.set(_RegistryState())
        call_token = self._active_tool_call_var.set(None)
        try:
            yield self
        finally:
            self._active_tool_call_var.reset(call_token)
            self._state_var.reset(state_token)

    def bind_tool_output(self, tool_call_id: str, provenance: Provenance) -> None:
        if not tool_call_id:
            return
        state = self._state_var.get()
        state.tool_outputs[tool_call_id] = provenance

    def bind_model_response(self, response_id: str, provenance: Provenance) -> None:
        if not response_id:
            return
        state = self._state_var.get()
        state.model_responses[response_id] = provenance

    def bind_generated_tool_call(
        self,
        tool_call_id: str,
        provenance: Provenance,
    ) -> None:
        if not tool_call_id:
            return
        state = self._state_var.get()
        state.generated_tool_calls[tool_call_id] = provenance

    def bind_conversation(
        self,
        conversation_id: str,
        provenance: Provenance,
    ) -> None:
        if not conversation_id:
            return
        state = self._state_var.get()
        existing = state.conversations.get(conversation_id, Provenance.empty())
        state.conversations[conversation_id] = existing.merge(provenance)

    def provenance_for_tool_call(self, tool_call_id: str) -> Provenance:
        state = self._state_var.get()
        return state.generated_tool_calls.get(tool_call_id, Provenance.empty())

    def provenance_for_model_input(
        self,
        input_items: Any,
        *,
        system_instructions: Any = None,
        prompt: Any = None,
        previous_response_id: str | None = None,
        conversation_id: str | None = None,
    ) -> ModelInputProvenance:
        state = self._state_var.get()
        provenances = [
            provenance_of(system_instructions),
            provenance_of(input_items),
            provenance_of(prompt),
        ]
        unknown: list[str] = []

        for call_id in _tool_output_ids(input_items):
            provenance = state.tool_outputs.get(call_id)
            if provenance is None:
                unknown.append(f"tool_call:{call_id}")
            else:
                provenances.append(provenance)

        if previous_response_id:
            provenance = state.model_responses.get(previous_response_id)
            if provenance is None:
                unknown.append(f"response:{previous_response_id}")
            else:
                provenances.append(provenance)

        if conversation_id:
            provenance = state.conversations.get(conversation_id)
            if provenance is None:
                unknown.append(f"conversation:{conversation_id}")
            else:
                provenances.append(provenance)

        return ModelInputProvenance(
            provenance=merge_provenance(provenances),
            unknown_context_ids=tuple(dict.fromkeys(unknown)),
        )

    def bind_model_artifacts(
        self,
        response: Any,
        provenance: Provenance,
        *,
        conversation_id: str | None = None,
    ) -> ModelBinding:
        response_id = _response_id(response)
        tool_call_ids = tuple(dict.fromkeys(_generated_tool_call_ids(response)))

        if response_id:
            self.bind_model_response(response_id, provenance)
        for tool_call_id in tool_call_ids:
            self.bind_generated_tool_call(tool_call_id, provenance)
        if conversation_id:
            self.bind_conversation(conversation_id, provenance)

        return ModelBinding(
            response_id=response_id,
            tool_call_ids=tool_call_ids,
        )

    @contextmanager
    def activate_tool_call(self, tool_call_id: str | None) -> Iterator[None]:
        token = self._active_tool_call_var.set(tool_call_id)
        try:
            yield
        finally:
            self._active_tool_call_var.reset(token)

    def prepare_tool_arguments(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        call_id = self._active_tool_call_var.get()
        if not call_id:
            return args, kwargs
        provenance = self.provenance_for_tool_call(call_id)
        if not provenance.labels and not provenance.sources:
            return args, kwargs
        return (
            tuple(track_with_provenance(item, provenance) for item in args),
            {
                key: track_with_provenance(value, provenance)
                for key, value in kwargs.items()
            },
        )

    def bind_active_tool_output(self, provenance: Provenance) -> None:
        call_id = self._active_tool_call_var.get()
        if call_id:
            self.bind_tool_output(call_id, provenance)


def _tool_output_ids(value: Any) -> list[str]:
    identifiers: list[str] = []
    for item in _walk_values(value):
        item_type = _string_field(item, "type")
        if item_type not in _TOOL_OUTPUT_TYPES:
            continue
        identifier = _string_field(item, "call_id") or _string_field(
            item,
            "tool_call_id",
        )
        if identifier:
            identifiers.append(identifier)
    return identifiers


def _generated_tool_call_ids(value: Any) -> list[str]:
    identifiers: list[str] = []
    for item in _walk_values(value):
        item_type = _string_field(item, "type")
        if item_type not in {"function_call", "tool_call"}:
            continue
        identifier = _string_field(item, "call_id") or _string_field(
            item,
            "tool_call_id",
        )
        if identifier:
            identifiers.append(identifier)
    return identifiers


def _response_id(value: Any) -> str | None:
    response_id = _string_field(value, "response_id")
    if response_id:
        return response_id
    if _string_field(value, "type") != "response.completed":
        return None
    response = _field(value, "response")
    return _string_field(response, "id")


def _walk_values(value: Any) -> Iterator[Any]:
    pending = [value]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if current is None or isinstance(current, (str, bytes, int, float, bool)):
            continue
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        yield current

        if isinstance(current, Mapping):
            pending.extend(current.values())
        elif isinstance(current, (list, tuple, set, frozenset)):
            pending.extend(current)
        else:
            values = getattr(current, "__dict__", None)
            if isinstance(values, dict):
                pending.extend(values.values())


def _string_field(value: Any, name: str) -> str | None:
    field = _field(value, name)
    if field is None:
        return None
    return str(field)


def _field(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)
