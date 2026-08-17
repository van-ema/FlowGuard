from __future__ import annotations

from collections.abc import Iterable
from copy import copy
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

from ..provenance import Provenance
from ..runtime import FlowguardRuntime
from ..tools import FlowguardTool
from ..tracked import provenance_of, untrack_value

_PROTECTED_RUNTIME_ATTR = "_flowguard_protected_runtime"


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
    ) -> None:
        self.runtime = runtime
        self.model_provider = model_provider
        self.provider_name = provider_name
        self.trust_zone = trust_zone
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
                    tool = _wrap_function_tool(tool, self.runtime)
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
) -> FunctionTool:
    """Wrap an SDK FunctionTool while keeping provenance in the sidecar."""

    invoke = getattr(tool, "on_invoke_tool", None)
    if invoke is None:
        return tool

    protected_runtime = getattr(tool, _PROTECTED_RUNTIME_ATTR, None)
    if protected_runtime is not None:
        _require_same_runtime(tool, runtime, "tool")
        return tool

    # Keep the original tool unchanged and preserve its schema and SDK options.
    protected_tool = copy(tool)
    invoke = protected_tool.on_invoke_tool

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
        # Nested Flowguard tools use the active ID to restore tracked arguments.
        with runtime.provenance_context.activate_tool_call(call_id):
            result = await invoke(context, arguments_json)
        output_provenance = input_provenance.merge(provenance_of(result))
        if call_id:
            # Existing SDK tools may serialize away tracked Python subclasses.
            runtime.provenance_context.bind_tool_output(call_id, output_provenance)
        # The plain value crosses the SDK boundary; provenance stays sidecar.
        return untrack_value(result)

    protected_tool.on_invoke_tool = guarded_invoke
    setattr(protected_tool, _PROTECTED_RUNTIME_ATTR, runtime)
    return protected_tool


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
