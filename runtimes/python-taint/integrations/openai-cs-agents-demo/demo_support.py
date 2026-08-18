from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INTEGRATION_ROOT = Path(__file__).resolve().parent
UPSTREAM_BACKEND = INTEGRATION_ROOT / "upstream" / "python-backend"


@dataclass(slots=True)
class DemoAgentContext:
    """Minimal context required by the native airline tools and instructions."""

    state: Any

    async def stream(self, event: Any) -> None:
        # The terminal demos do not render upstream ChatKit progress events.
        return None


def load_upstream_graph() -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Load the unchanged upstream application and hidden guardrail agents."""

    if not UPSTREAM_BACKEND.is_dir():
        raise RuntimeError("initialize the openai-cs-agents-demo git submodule first")
    sys.path.insert(0, str(UPSTREAM_BACKEND))
    try:
        from airline.agents import (
            booking_cancellation_agent,
            faq_agent,
            flight_information_agent,
            refunds_compensation_agent,
            seat_special_services_agent,
            triage_agent,
        )
        from airline.guardrails import guardrail_agent, jailbreak_guardrail_agent
    except ModuleNotFoundError as err:
        raise RuntimeError(
            "install the upstream Python backend requirements before running "
            f"the demo; missing module: {err.name}"
        ) from err

    return (
        (
            triage_agent,
            booking_cancellation_agent,
            faq_agent,
            flight_information_agent,
            refunds_compensation_agent,
            seat_special_services_agent,
        ),
        (guardrail_agent, jailbreak_guardrail_agent),
    )


def create_demo_context() -> DemoAgentContext:
    """Create fresh per-run state for native context-aware airline tools."""

    from airline.context import create_initial_context

    return DemoAgentContext(state=create_initial_context())
