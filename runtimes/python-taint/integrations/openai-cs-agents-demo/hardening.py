from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents import Agent, FunctionTool, function_tool
from agents.models.interface import ModelProvider

from flowguard import (
    FlowguardBlocked,
    FlowguardRuntime,
    ModelEgressPolicy,
    ModelRule,
    SourceRef,
    ToolSinkRule,
    ToolSourceRule,
)

# Integration-defined label; its behavior comes from the rules below.
CUSTOMER_DATA_LABEL = "CustomerData"
CUSTOMER_DATA_TO_NETWORK_POLICY = "CustomerDataToNetwork"
CUSTOMER_RECORD_SOURCE_TOOL = "get_trip_details"
UPLOAD_CUSTOMER_RECORD_TOOL = "upload_customer_record"

AIRLINE_CUSTOMER_DATA_TOOLS = (
    "get_trip_details",
    "book_new_flight",
    "cancel_flight",
    "update_seat",
    "assign_special_service_seat",
    "issue_compensation",
)


@dataclass(frozen=True, slots=True)
class HardenedAirlineGraph:
    runtime: FlowguardRuntime
    root_agent: Agent[Any]
    upload_tool: FunctionTool


def flowguard_block_from(error: BaseException) -> FlowguardBlocked | None:
    """Find a Flowguard block wrapped by an agent-framework exception."""

    pending: list[BaseException] = [error]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, FlowguardBlocked):
            return current
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return None


def create_airline_runtime(
    *,
    provider_name: str = "openai",
    trust_zone: str = "external",
    event_log: str | Path | None = None,
) -> FlowguardRuntime:
    """Create the demo policy that permits one approved model boundary."""

    destination = f"model:{provider_name}:*:{trust_zone}"
    return FlowguardRuntime(
        event_log=event_log,
        model_policy=ModelEgressPolicy(
            [
                ModelRule.allow_and_propagate(
                    labels={CUSTOMER_DATA_LABEL},
                    destinations={destination},
                    policy="ApprovedCustomerDataToModel",
                )
            ]
        ),
    )


def airline_source_rules() -> tuple[ToolSourceRule, ...]:
    """Classify customer-specific outputs from unchanged upstream tools."""

    return tuple(
        ToolSourceRule(
            tool_name,
            labels={CUSTOMER_DATA_LABEL},
            source=SourceRef.tool(tool_name),
        )
        for tool_name in AIRLINE_CUSTOMER_DATA_TOOLS
    )


def add_customer_export_tool(
    root_agent: Agent[Any],
    *,
    leak_target: str,
    receiver: Any,
) -> FunctionTool:
    """Create and attach the demo-only export tool to an existing agent."""

    existing_names = {
        name
        for tool in root_agent.tools
        if isinstance((name := getattr(tool, "name", None)), str)
    }
    if UPLOAD_CUSTOMER_RECORD_TOOL in existing_names:
        raise ValueError(
            f"agent already contains tool {UPLOAD_CUSTOMER_RECORD_TOOL}"
        )

    # Demo-only sink: this export tool is not part of the upstream agent graph.
    @function_tool(
        name_override=UPLOAD_CUSTOMER_RECORD_TOOL,
        description_override="Upload customer data to an external support archive.",
        failure_error_function=None,
    )
    def upload_customer_record(payload: str) -> str:
        receiver.post(leak_target, data=payload)
        return "Customer data uploaded"

    root_agent.tools = [*root_agent.tools, upload_customer_record]
    return upload_customer_record


def harden_airline_agent_graph(
    runtime: FlowguardRuntime,
    root_agent: Agent[Any],
    *,
    leak_target: str,
    receiver: Any,
    model_provider: ModelProvider | None = None,
    provider_name: str = "openai",
    trust_zone: str = "external",
    additional_agents: Iterable[Agent[Any]] = (),
) -> HardenedAirlineGraph:
    """Protect native customer-data sources and the controlled export sink."""

    source_names = {getattr(tool, "name", None) for tool in root_agent.tools}
    if CUSTOMER_RECORD_SOURCE_TOOL not in source_names:
        raise ValueError(
            f"agent graph root must expose {CUSTOMER_RECORD_SOURCE_TOOL}"
        )

    # Add the custom demo sink before Flowguard wraps the complete graph.
    upload_tool = add_customer_export_tool(
        root_agent,
        leak_target=leak_target,
        receiver=receiver,
    )
    runtime.protect_openai_agent_graph(
        root_agent,
        model_provider=model_provider,
        provider_name=provider_name,
        trust_zone=trust_zone,
        additional_agents=additional_agents,
        source_rules=airline_source_rules(),
        sink_rules=(
            ToolSinkRule(
                UPLOAD_CUSTOMER_RECORD_TOOL,
                labels={CUSTOMER_DATA_LABEL},
                policy=CUSTOMER_DATA_TO_NETWORK_POLICY,
                target=leak_target,
            ),
        ),
    )
    return HardenedAirlineGraph(
        runtime=runtime,
        root_agent=root_agent,
        upload_tool=upload_tool,
    )
