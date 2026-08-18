from typing import Any

from .exceptions import FlowguardBlocked
from .executor import GeneratedCodeResult
from .model import (
    ModelDestination,
    ModelEgressAction,
    ModelEgressPolicy,
    ModelRule,
)
from .protect import ProtectionContext
from .provenance import Provenance, SourceRef
from .provenance_context import ProvenanceContext
from .report import FlowguardReport
from .runtime import FlowguardRuntime
from .tracked import TrackedBytes, TrackedStr
from .tools import FlowguardTool, ToolCallContext, ToolSinkRule, ToolSourceRule


def protect_openai_agent_graph(*args: Any, **kwargs: Any) -> Any:
    """Load the optional OpenAI adapter and protect an existing agent graph."""

    try:
        from .adapters.openai_agents import protect_openai_agent_graph as protect
    except ModuleNotFoundError as err:
        if err.name != "agents":
            raise
        raise RuntimeError(
            "OpenAI Agents SDK is not installed. Install openai-agents before "
            "protecting an agent graph."
        ) from err
    return protect(*args, **kwargs)

__all__ = [
    "FlowguardBlocked",
    "FlowguardReport",
    "FlowguardRuntime",
    "FlowguardTool",
    "GeneratedCodeResult",
    "ModelDestination",
    "ModelEgressAction",
    "ModelEgressPolicy",
    "ModelRule",
    "ProtectionContext",
    "Provenance",
    "ProvenanceContext",
    "SourceRef",
    "TrackedBytes",
    "TrackedStr",
    "ToolCallContext",
    "ToolSinkRule",
    "ToolSourceRule",
    "protect_openai_agent_graph",
]
