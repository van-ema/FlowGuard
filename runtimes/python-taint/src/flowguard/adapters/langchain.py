from __future__ import annotations

from functools import wraps
from typing import Any

from ..tools import FlowguardTool


def as_langchain_tool(tool: FlowguardTool) -> Any:
    """Adapt a Flowguard tool for LangChain and LangGraph tool execution."""

    try:
        from langchain_core.tools import StructuredTool, create_schema_from_function
    except ImportError as err:
        raise RuntimeError(
            "LangChain Core is not installed. Install the optional "
            "langchain-core package before calling as_langchain_tool()."
        ) from err

    # Preserve the original signature so LangChain infers the correct input schema.
    @wraps(tool.function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        return tool(*args, **kwargs)

    # A JSON schema advertises the same inputs without Pydantic replacing tracked
    # str/bytes subclasses with plain values before Flowguard sees them.
    input_model = create_schema_from_function(tool.name, wrapped)
    args_schema = input_model.model_json_schema()

    return StructuredTool.from_function(
        func=wrapped,
        name=tool.name,
        description=tool.description or "",
        args_schema=args_schema,
    )
