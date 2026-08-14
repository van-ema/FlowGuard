from __future__ import annotations

from functools import wraps
from typing import Any

from ..tools import FlowguardTool
from ..tracked import untrack_value


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

    sdk_tool = function_tool(**kwargs)(wrapped)
    invoke = getattr(sdk_tool, "on_invoke_tool", None)
    if invoke is None:
        return sdk_tool

    async def guarded_invoke(context: Any, arguments_json: str) -> Any:
        call_id = getattr(context, "tool_call_id", None)
        if not isinstance(call_id, str):
            call_id = None
        with tool.runtime.provenance_context.activate_tool_call(call_id):
            result = await invoke(context, arguments_json)
        return untrack_value(result)

    sdk_tool.on_invoke_tool = guarded_invoke
    return sdk_tool
