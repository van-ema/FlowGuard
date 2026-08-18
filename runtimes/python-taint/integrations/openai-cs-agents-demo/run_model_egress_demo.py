from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TextIO

from demo_support import create_demo_context, load_upstream_graph
from flowguard import FlowguardRuntime
from hardening import (
    CUSTOMER_DATA_LABEL,
    CUSTOMER_DATA_TO_EXTERNAL_MODEL_POLICY,
    create_airline_runtime,
    create_model_egress_blocking_runtime,
    flowguard_block_from,
    protect_airline_agent_graph,
)

SENSITIVE_PROMPT = (
    "For this airline support request, call get_trip_details with a message "
    "mentioning Paris, New York, and Austin. Then summarize the returned "
    "itinerary for the customer."
)
PUBLIC_PROMPT = (
    "What is the airline baggage allowance? Use the FAQ tools when needed, "
    "then summarize the public policy. Do not retrieve trip details."
)
DemoCase = Literal[
    "baseline-sensitive",
    "protected-sensitive",
    "protected-public",
]


@dataclass(frozen=True, slots=True)
class DemoArtifacts:
    case: DemoCase
    result: str
    summary_path: Path
    report_path: Path
    events_path: Path
    blocked_policy: str


async def run_demo(
    *,
    case: DemoCase,
    out_dir: Path,
    name: str,
    model: str | None,
    output: TextIO,
) -> DemoArtifacts:
    protected = case != "baseline-sensitive"
    sensitive = case != "protected-public"
    runtime, root_agent = _build_graph(
        model=model,
        block_customer_data=protected,
    )

    from agents import Runner

    blocked_policy = ""
    blocked_explanation = ""
    prompt = SENSITIVE_PROMPT if sensitive else PUBLIC_PROMPT
    with runtime.provenance_context.scope():
        try:
            await Runner.run(
                root_agent,
                input=prompt,
                context=create_demo_context(),
                max_turns=8,
            )
        except Exception as err:
            block = flowguard_block_from(err)
            if block is None:
                raise
            blocked_policy = block.policy
            blocked_explanation = block.explanation

    report = runtime.report()
    if case == "baseline-sensitive":
        allowed_customer_data = [
            call
            for call in report.model_calls
            if CUSTOMER_DATA_LABEL in call.labels
            and call.action == "ALLOW_AND_PROPAGATE"
        ]
        if blocked_policy or report.summary.violation_count or not allowed_customer_data:
            raise AssertionError(
                "baseline did not send labeled customer data to the model"
            )
        result = "DATA_REACHED_MODEL"
    elif case == "protected-sensitive":
        if blocked_policy != CUSTOMER_DATA_TO_EXTERNAL_MODEL_POLICY:
            raise AssertionError(
                "expected CustomerDataToExternalModel, got "
                f"{blocked_policy or 'no block'}"
            )
        if report.summary.violation_count != 1:
            raise AssertionError("protected sensitive case must produce one block")
        result = "BLOCKED"
    else:
        if blocked_policy or report.summary.violation_count:
            raise AssertionError("public case was unexpectedly blocked")
        if any(CUSTOMER_DATA_LABEL in call.labels for call in report.model_calls):
            raise AssertionError("public case unexpectedly accessed customer data")
        result = "ALLOWED"

    out_dir.mkdir(parents=True, exist_ok=True)
    artifact_name = f"{name}.{case}"
    summary_path = out_dir / f"{artifact_name}.summary.json"
    report_path = out_dir / f"{artifact_name}.report.json"
    events_path = out_dir / f"{artifact_name}.events.jsonl"
    summary_path.write_text(
        json.dumps(
            {
                "case": case,
                "result": result,
                "policy": blocked_policy or None,
                "violations": report.summary.violation_count,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    report.write_json(report_path)
    report.write_jsonl(events_path)

    _print(output, "Flowguard Native Model Egress Demo")
    _print(output, f"case: {case}")
    _print(
        output,
        f"result: {result}{f' {blocked_policy}' if blocked_policy else ''}",
    )
    if blocked_explanation:
        _print(output, blocked_explanation)
    _print(output, f"summary: {summary_path}")
    _print(output, f"report: {report_path}")
    _print(output, f"events: {events_path}")

    return DemoArtifacts(
        case=case,
        result=result,
        summary_path=summary_path,
        report_path=report_path,
        events_path=events_path,
        blocked_policy=blocked_policy,
    )


async def run_interactive_demo(
    *,
    out_dir: Path,
    name: str,
    model: str | None,
    output: TextIO,
) -> None:
    """Run isolated prompts against the native graph with blocking enabled."""

    runtime, root_agent = _build_graph(
        model=model,
        block_customer_data=True,
    )
    from agents import Runner

    _print(output, "Flowguard Interactive Model Egress Demo")
    _print(output, "Each prompt uses fresh airline and provenance state.")
    _print(output, "Try: What is the baggage allowance?")
    _print(output, "Try: Summarize my Paris to New York to Austin trip.")
    _print(output, "Type quit to exit.")

    turn = 0
    while True:
        try:
            prompt = input("flowguard> ").strip()
        except EOFError:
            prompt = "quit"
        if prompt.lower() in {"quit", "exit", ":q"}:
            break
        if not prompt:
            continue

        turn += 1
        with runtime.provenance_context.scope():
            try:
                result = await Runner.run(
                    root_agent,
                    input=prompt,
                    context=create_demo_context(),
                    max_turns=8,
                )
            except Exception as err:
                block = flowguard_block_from(err)
                if block is None:
                    _print(output, f"ERROR {type(err).__name__}: {err}")
                else:
                    _print(output, f"BLOCKED {block.policy}")
                    _print(output, block.explanation)
            else:
                _print(output, f"ALLOWED {result.final_output}")

        report_path, events_path = _write_interactive_artifacts(
            runtime,
            out_dir=out_dir,
            name=name,
        )
        _print(output, f"turn={turn} report={report_path} events={events_path}")


def _build_graph(
    *,
    model: str | None,
    block_customer_data: bool,
) -> tuple[FlowguardRuntime, Any]:
    agents, guardrail_agents = load_upstream_graph()
    root_agent = agents[0]
    if model:
        for agent in (*agents, *guardrail_agents):
            agent.model = model
    runtime = (
        create_model_egress_blocking_runtime()
        if block_customer_data
        else create_airline_runtime()
    )
    protect_airline_agent_graph(
        runtime,
        root_agent,
        additional_agents=guardrail_agents,
    )
    return runtime, root_agent


def _write_interactive_artifacts(
    runtime: FlowguardRuntime,
    *,
    out_dir: Path,
    name: str,
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = runtime.report()
    report_path = out_dir / f"{name}.interactive.report.json"
    events_path = out_dir / f"{name}.interactive.events.jsonl"
    report.write_json(report_path)
    report.write_jsonl(events_path)
    return report_path, events_path


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one native OpenAI customer-data model-egress case."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--case",
        choices=(
            "baseline-sensitive",
            "protected-sensitive",
            "protected-public",
        ),
    )
    mode.add_argument("--interactive", action="store_true")
    parser.add_argument("--out-dir", type=Path, default=Path("logs"))
    parser.add_argument("--name", default="openai-cs-model-egress-demo")
    parser.add_argument(
        "--model",
        default=os.environ.get("FLOWGUARD_OPENAI_CS_MODEL", "gpt-5-nano"),
    )
    return parser.parse_args(argv)


def _print(output: TextIO, text: str) -> None:
    print(text, file=output)


def main(argv: list[str] | None = None) -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY is required for the live demo", file=sys.stderr)
        return 2
    args = _parse_args(argv)
    if args.interactive:
        asyncio.run(
            run_interactive_demo(
                out_dir=args.out_dir,
                name=args.name,
                model=args.model,
                output=sys.stdout,
            )
        )
    else:
        asyncio.run(
            run_demo(
                case=args.case,
                out_dir=args.out_dir,
                name=args.name,
                model=args.model,
                output=sys.stdout,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
