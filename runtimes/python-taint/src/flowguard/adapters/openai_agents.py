from __future__ import annotations

from collections.abc import Iterable
from copy import copy
from dataclasses import dataclass
from functools import wraps
from typing import Any

from agents import (
    Agent,
    FunctionTool,
    Handoff,
    RunConfig,
    RunContextWrapper,
    function_tool,
)
from agents.models.interface import ModelProvider
from agents.tool_context import ToolContext

from ..decisions import Decision
from ..exceptions import FlowguardBlocked
from ..provenance import Provenance
from ..runtime import FlowguardRuntime
from ..tools import FlowguardTool, ToolSinkRule, ToolSourceRule
from ..tracked import provenance_of, untrack_value

_PROTECTED_RUNTIME_ATTR = "_flowguard_protected_runtime"
_PROTECTED_TOOL_STATE_ATTR = "_flowguard_tool_protection_state"


@dataclass(slots=True)
class _ToolProtectionState:
    runtime: FlowguardRuntime
    source_provenance: Provenance
    sink_rules: tuple[ToolSinkRule, ...]


def as_openai_tool(tool: FlowguardTool) -> FunctionTool:
    """Expose a Flowguard tool to the Agents SDK without losing provenance."""

    @wraps(tool.function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        return tool(*args, **kwargs)

    kwargs: dict[str, Any] = {}
    if tool.name != tool.function.__name__:
        kwargs["name_override"] = tool.name
    if tool.description is not None:
        kwargs["description_override"] = tool.description
    # A policy block must stop the agent run, not become model-visible tool text.
    kwargs["failure_error_function"] = None

    sdk_tool = function_tool(**kwargs)(wrapped)
    return _wrap_function_tool(sdk_tool, tool.runtime)


def protect_openai_agent_graph(
    runtime: FlowguardRuntime,
    root_agent: Agent[Any],
    *,
    model_provider: ModelProvider | None = None,
    provider_name: str = "openai",
    trust_zone: str = "external",
    additional_agents: Iterable[Agent[Any]] = (),
    source_rules: Iterable[ToolSourceRule] = (),
    sink_rules: Iterable[ToolSinkRule] = (),
) -> Agent[Any]:
    """Protect an existing OpenAI Agents SDK graph in place.

    Direct and configured handoff targets are traversed by identity, so cyclic
    graphs are safe. Dynamic handoff targets are protected before the SDK runs
    them. Pass agents hidden inside callbacks, such as guardrail agents, through
    ``additional_agents`` because the SDK graph does not expose those closures.
    """

    if not isinstance(root_agent, Agent):
        raise TypeError("root_agent must be an OpenAI Agents SDK Agent")

    if model_provider is None:
        model_provider = RunConfig().model_provider

    protector = _AgentGraphProtector(
        runtime=runtime,
        model_provider=model_provider,
        provider_name=provider_name,
        trust_zone=trust_zone,
        source_rules=source_rules,
        sink_rules=sink_rules,
    )
    protector.protect(root_agent)
    for agent in additional_agents:
        protector.protect(agent)
    return root_agent


class _AgentGraphProtector:
    def __init__(
        self,
        *,
        runtime: FlowguardRuntime,
        model_provider: ModelProvider,
        provider_name: str,
        trust_zone: str,
        source_rules: Iterable[ToolSourceRule],
        sink_rules: Iterable[ToolSinkRule],
    ) -> None:
        self.runtime = runtime
        self.model_provider = model_provider
        self.provider_name = provider_name
        self.trust_zone = trust_zone
        self.source_provenance = _source_provenance_by_tool(source_rules)
        self.sink_rules = _sink_rules_by_tool(sink_rules)
        self._visited_agents: set[int] = set()

    def protect(self, root_agent: Agent[Any]) -> None:
        if not isinstance(root_agent, Agent):
            raise TypeError("all protected graph roots must be OpenAI SDK Agents")

        pending = [root_agent]
        while pending:
            agent = pending.pop()
            identity = id(agent)
            if identity in self._visited_agents:
                continue
            self._visited_agents.add(identity)

            self._protect_model(agent)
            protected_tools: list[Any] = []
            for tool in agent.tools:
                nested_agent = getattr(tool, "_agent_instance", None)
                if isinstance(nested_agent, Agent):
                    pending.append(nested_agent)
                if isinstance(tool, FunctionTool):
                    tool = _wrap_function_tool(
                        tool,
                        self.runtime,
                        source_provenance=self.source_provenance.get(
                            tool.name,
                            Provenance.empty(),
                        ),
                        sink_rules=self.sink_rules.get(tool.name, ()),
                    )
                protected_tools.append(tool)
            agent.tools = protected_tools

            for handoff in agent.handoffs:
                if isinstance(handoff, Agent):
                    pending.append(handoff)
                    continue
                if not isinstance(handoff, Handoff):
                    continue
                target = _configured_handoff_target(handoff)
                if isinstance(target, Agent):
                    pending.append(target)
                self._protect_handoff(handoff)

    def _protect_model(self, agent: Agent[Any]) -> None:
        from .openai_model import FlowguardOpenAIModel

        configured_model = agent.model
        if isinstance(configured_model, FlowguardOpenAIModel):
            _require_same_runtime(configured_model, self.runtime, "model")
            return

        if isinstance(configured_model, str) or configured_model is None:
            delegate = self.model_provider.get_model(configured_model)
            model_name = configured_model or "default"
        else:
            delegate = configured_model
            model_name = _model_name(delegate)

        if isinstance(delegate, FlowguardOpenAIModel):
            _require_same_runtime(delegate, self.runtime, "model")
            agent.model = delegate
            return

        agent.model = self.runtime.guard_openai_model(
            delegate,
            provider=self.provider_name,
            model_name=model_name,
            trust_zone=self.trust_zone,
        )

    def _protect_handoff(self, handoff: Handoff[Any, Any]) -> None:
        protected_runtime = getattr(handoff, _PROTECTED_RUNTIME_ATTR, None)
        if protected_runtime is not None:
            _require_same_runtime(handoff, self.runtime, "handoff")
            return

        invoke = handoff.on_invoke_handoff

        async def guarded_handoff(
            context: RunContextWrapper[Any],
            arguments_json: str,
        ) -> Agent[Any]:
            target = await invoke(context, arguments_json)
            self.protect(target)
            return target

        handoff.on_invoke_handoff = guarded_handoff
        setattr(handoff, _PROTECTED_RUNTIME_ATTR, self.runtime)


def _wrap_function_tool(
    tool: FunctionTool,
    runtime: FlowguardRuntime,
    *,
    source_provenance: Provenance | None = None,
    sink_rules: Iterable[ToolSinkRule] = (),
) -> FunctionTool:
    """Wrap an SDK FunctionTool while keeping provenance in the sidecar."""

    invoke = getattr(tool, "on_invoke_tool", None)
    if invoke is None:
        return tool

    declared_source = source_provenance or Provenance.empty()
    declared_sinks = tuple(sink_rules)
    protected_runtime = getattr(tool, _PROTECTED_RUNTIME_ATTR, None)
    if protected_runtime is not None:
        _require_same_runtime(tool, runtime, "tool")
        state = getattr(tool, _PROTECTED_TOOL_STATE_ATTR, None)
        if isinstance(state, _ToolProtectionState):
            state.source_provenance = state.source_provenance.merge(declared_source)
            state.sink_rules = tuple(
                dict.fromkeys((*state.sink_rules, *declared_sinks))
            )
        return tool

    # Keep the original tool unchanged and preserve its schema and SDK options.
    # For example, get_trip_details.on_invoke_tool becomes guarded_invoke;
    # guarded_invoke checks provenance, calls the original callback, and then
    # labels its output before returning it to the SDK.
    protected_tool = copy(tool)
    invoke = protected_tool.on_invoke_tool
    state = _ToolProtectionState(
        runtime=runtime,
        source_provenance=declared_source,
        sink_rules=declared_sinks,
    )

    async def guarded_invoke(
        context: ToolContext[Any],
        arguments_json: str,
    ) -> Any:
        call_id = getattr(context, "tool_call_id", None)
        if not isinstance(call_id, str):
            call_id = None
        # The model adapter binds provenance to each generated tool call ID.
        input_provenance = (
            runtime.provenance_context.provenance_for_tool_call(call_id)
            if call_id
            else Provenance.empty()
        )

        # Before invoking the tool, guarded_invoke()
        # compares the call provenance with every applicable rule
        for sink_rule in state.sink_rules:
            if not sink_rule.matches(input_provenance):
                continue
            decision = Decision.block_sensitive_to_tool(
                sink_rule.target,
                input_provenance,
                policy=sink_rule.policy,
            )
            runtime.emitter.emit(
                "tool_call_blocked",
                name=protected_tool.name,
                target=decision.target,
                policy=decision.policy,
                explanation=decision.explanation,
                labels=sorted(input_provenance.labels),
                sources=[
                    source.display() for source in input_provenance.sources
                ],
                transforms=[
                    transform.to_dict()
                    for transform in input_provenance.transforms
                ],
                scope_id=runtime.current_scope_id(),
            )
            raise FlowguardBlocked(decision)
        # Existing tools get transparent file, network, and subprocess guards.
        with runtime.protect():
            # Nested Flowguard tools use the active ID to restore tracked arguments.
            with runtime.provenance_context.activate_tool_call(call_id):
                result = await invoke(context, arguments_json)
        output_provenance = input_provenance.merge(provenance_of(result)).merge(
            state.source_provenance
        )
        if call_id:
            # Existing SDK tools may serialize away tracked Python subclasses.
            runtime.provenance_context.bind_tool_output(call_id, output_provenance)
        if state.source_provenance.labels:
            runtime.emitter.emit(
                "tool_output_labeled",
                name=protected_tool.name,
                labels=sorted(output_provenance.labels),
                sources=[source.display() for source in output_provenance.sources],
                transforms=[
                    transform.to_dict()
                    for transform in output_provenance.transforms
                ],
                scope_id=runtime.current_scope_id(),
            )
        # The plain value crosses the SDK boundary; provenance stays sidecar.
        return untrack_value(result)

    protected_tool.on_invoke_tool = guarded_invoke
    setattr(protected_tool, _PROTECTED_RUNTIME_ATTR, runtime)
    setattr(protected_tool, _PROTECTED_TOOL_STATE_ATTR, state)
    return protected_tool


def _source_provenance_by_tool(
    rules: Iterable[ToolSourceRule],
) -> dict[str, Provenance]:
    mapped: dict[str, Provenance] = {}
    for rule in rules:
        current = mapped.get(rule.tool_name, Provenance.empty())
        mapped[rule.tool_name] = current.merge(rule.provenance)
    return mapped


def _sink_rules_by_tool(
    rules: Iterable[ToolSinkRule],
) -> dict[str, tuple[ToolSinkRule, ...]]:
    mapped: dict[str, list[ToolSinkRule]] = {}
    for rule in rules:
        mapped.setdefault(rule.tool_name, []).append(rule)
    return {name: tuple(tool_rules) for name, tool_rules in mapped.items()}


def _configured_handoff_target(handoff: Handoff[Any, Any]) -> Agent[Any] | None:
    reference = getattr(handoff, "_agent_ref", None)
    target = reference() if callable(reference) else None
    return target if isinstance(target, Agent) else None


def _model_name(model: Any) -> str:
    for attribute in ("model", "model_name", "name"):
        value = getattr(model, attribute, None)
        if isinstance(value, str) and value:
            return value
    return type(model).__name__


def _require_same_runtime(
    value: Any,
    runtime: FlowguardRuntime,
    kind: str,
) -> None:
    if getattr(value, _PROTECTED_RUNTIME_ATTR, None) is runtime:
        return
    if getattr(value, "_runtime", None) is runtime:
        return
    raise RuntimeError(f"OpenAI {kind} is already protected by another runtime")
