from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from flowguard import FlowguardBlocked, FlowguardRuntime

DEMO_SECRET = "FLOWGUARD MODEL GUARD PRIVATE KEY"


@dataclass(frozen=True, slots=True)
class ModelGuardDemoArtifacts:
    report_path: Path
    events_path: Path
    blocked_policy: str
    provider_call_count: int


async def run_demo(
    *,
    out_dir: Path,
    name: str,
    output: TextIO,
) -> ModelGuardDemoArtifacts:
    try:
        from agents import Agent, Runner
    except ImportError as err:
        raise RuntimeError(
            "OpenAI Agents SDK is not installed. Install openai-agents or run "
            "the Docker demo script."
        ) from err

    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = Path(tmpdir) / "id_rsa"
        secret_path.write_text(DEMO_SECRET, encoding="utf-8")
        runtime = FlowguardRuntime(secret_paths=[secret_path])

        @runtime.tool(name="read_secret", description="Read the configured file.")
        def read_secret(path: str) -> str:
            with runtime.open(path) as handle:
                return handle.read()

        delegate = _build_read_secret_model(secret_path)
        guarded_model = runtime.guard_openai_model(
            delegate,
            provider="demo-provider",
            model_name="demo-model",
            trust_zone="external",
        )
        agent = Agent(
            name="Flowguard Model Request Guard Demo",
            instructions="Use read_secret to inspect the configured file.",
            model=guarded_model,
            tools=[read_secret.as_openai_tool()],
        )

        blocked_policy = ""
        with runtime.provenance_context.scope():
            try:
                await Runner.run(agent, input="Read the configured secret file.")
            except FlowguardBlocked as err:
                blocked_policy = err.policy
                _print(output, "Flowguard Model Request Guard Demo")
                _print(output, f"result: BLOCKED {err.policy}")
                _print(output, err.explanation)

        if blocked_policy != "SecretToModel":
            raise AssertionError(
                f"expected SecretToModel, got {blocked_policy or 'no block'}"
            )
        if delegate.calls != 1:
            raise AssertionError(
                "expected one public model call and no sensitive second call, "
                f"got {delegate.calls}"
            )

        report = runtime.report()
        report_path = out_dir / f"{name}.report.json"
        events_path = out_dir / f"{name}.events.jsonl"
        report.write_json(report_path)
        report.write_jsonl(events_path)

        _print(output, f"provider_calls={delegate.calls}")
        _print(output, "sensitive_provider_calls=0")
        _print(output, "")
        _print(output, "reports:")
        _print(output, f"  {report_path}")
        _print(output, f"  {events_path}")
        _print(output, "summary:")
        _print(output, f"  violations={report.summary.violation_count}")
        _print(output, f"  model_requests={report.summary.model_request_count}")

        return ModelGuardDemoArtifacts(
            report_path=report_path,
            events_path=events_path,
            blocked_policy=blocked_policy,
            provider_call_count=delegate.calls,
        )


def _build_read_secret_model(secret_path: Path) -> Any:
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import ResponseFunctionToolCall

    class ReadSecretModel(Model):
        def __init__(self) -> None:
            self.calls = 0

        async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
            self.calls += 1
            return ModelResponse(
                output=[
                    ResponseFunctionToolCall(
                        arguments=json.dumps({"path": str(secret_path)}),
                        call_id="call-read-secret",
                        name="read_secret",
                        type="function_call",
                    )
                ],
                usage=Usage(),
                response_id="resp-read-secret",
            )

        def stream_response(self, *args: Any, **kwargs: Any) -> Any:
            async def empty_stream() -> Any:
                if False:
                    yield None

            return empty_stream()

    return ReadSecretModel()


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the offline OpenAI Agents SDK model-egress demo."
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("logs"),
        help="Directory where report artifacts are written.",
    )
    parser.add_argument(
        "--name",
        default="model-request-guard-demo",
        help="Base artifact name.",
    )
    return parser.parse_args(argv)


def _print(output: TextIO, text: str) -> None:
    print(text, file=output)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    asyncio.run(
        run_demo(
            out_dir=args.out_dir,
            name=args.name,
            output=sys.stdout,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
