from __future__ import annotations

from functools import wraps
from typing import Any

from ..tools import FlowguardTool


def as_openai_tool(tool: FlowguardTool) -> Any:
    try:
        from agents import function_tool
    except ImportError as err:
        raise RuntimeError(
            "OpenAI Agents SDK is not installed. Install the optional "
            "agents package before calling as_openai_tool()."
        ) from err

    @wraps(tool.function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        return tool(*args, **kwargs)

    kwargs: dict[str, Any] = {}
    if tool.name != tool.function.__name__:
        kwargs["name_override"] = tool.name
    if tool.description is not None:
        kwargs["description_override"] = tool.description

    return function_tool(**kwargs)(wrapped)

