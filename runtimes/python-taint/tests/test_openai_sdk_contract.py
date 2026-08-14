from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from flowguard import FlowguardBlocked, FlowguardRuntime

try:
    from agents import Agent, Runner
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import ResponseFunctionToolCall
except ImportError:
    Agent = Runner = ModelResponse = Model = Usage = ResponseFunctionToolCall = None


@unittest.skipUnless(Agent is not None, "OpenAI Agents SDK is not installed")
class OpenAISdkContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_runner_blocks_tool_output_before_second_model_call(self) -> None:
        class FakeSdkModel(Model):
            def __init__(self) -> None:
                self.calls = 0

            async def get_response(self, *args: Any, **kwargs: Any) -> Any:
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

        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path])

            @runtime.tool
            def read_secret(path: str) -> str:
                with runtime.open(path) as handle:
                    return handle.read()

            delegate = FakeSdkModel()
            guarded_model = runtime.guard_openai_model(
                delegate,
                provider="fake-openai",
                model_name="fake-model",
            )
            agent = Agent(
                name="Flowguard SDK contract test",
                model=guarded_model,
                tools=[read_secret.as_openai_tool()],
            )

            with self.assertRaises(FlowguardBlocked) as raised:
                await Runner.run(agent, input="Read the configured file.")

            self.assertEqual(raised.exception.policy, "SecretToModel")
            self.assertEqual(delegate.calls, 1)
            self.assertEqual(runtime.report().summary.violation_count, 1)


if __name__ == "__main__":
    unittest.main()
