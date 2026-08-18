from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

INTEGRATION_ROOT = Path(__file__).resolve().parent
UPSTREAM_BACKEND = INTEGRATION_ROOT / "upstream" / "python-backend"
sys.path.insert(0, str(UPSTREAM_BACKEND))

import main as upstream_main
from airline.agents import (  # noqa: E402
    booking_cancellation_agent,
    faq_agent,
    flight_information_agent,
    refunds_compensation_agent,
    seat_special_services_agent,
    triage_agent,
)
from airline.guardrails import guardrail_agent, jailbreak_guardrail_agent  # noqa: E402

from flowguard_server import FlowguardAirlineServer  # noqa: E402
from hardening import create_airline_runtime, harden_airline_agent_graph  # noqa: E402

LEAK_TARGET = "https://untrusted.example/collect"


class _BlockedReceiver:
    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        raise AssertionError("Flowguard must block before the receiver is called")

# These are unchanged upstream agents; Flowguard only wraps their boundaries.
_all_agents = (
    triage_agent,
    booking_cancellation_agent,
    faq_agent,
    flight_information_agent,
    refunds_compensation_agent,
    seat_special_services_agent,
)
# These upstream callback-owned agents must be listed because graph traversal
# cannot discover agents hidden inside guardrail callbacks.
_guardrail_agents = (guardrail_agent, jailbreak_guardrail_agent)
_model = os.environ.get("FLOWGUARD_OPENAI_CS_MODEL")
if _model:
    for _agent in (*_all_agents, *_guardrail_agents):
        _agent.model = _model

runtime = create_airline_runtime(
    event_log=os.environ.get("FLOWGUARD_OPENAI_CS_EVENT_LOG"),
)
harden_airline_agent_graph(
    runtime,
    triage_agent,
    leak_target=LEAK_TARGET,
    receiver=_BlockedReceiver(),
    additional_agents=_guardrail_agents,
)

# The upstream dependency reads this global for every FastAPI request.
upstream_main.chat_server = FlowguardAirlineServer(runtime)
app = upstream_main.app


@app.get("/flowguard/report")
async def flowguard_report() -> dict[str, Any]:
    """Return the content-safe Flowguard report for the running demo."""

    return runtime.report().to_dict()
