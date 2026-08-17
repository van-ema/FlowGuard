from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from flowguard import FlowguardBlocked
from flowguard.adapters.openai_model import FlowguardOpenAIModel

try:
    from agents import Agent, Runner
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import ResponseFunctionToolCall
except ImportError:
    Agent = Runner = ModelResponse = Model = Usage = None
    ResponseFunctionToolCall = None

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
HARDENING_PATH = (
    RUNTIME_ROOT
    / "integrations"
    / "openai-cs-agents-demo"
    / "hardening.py"
)


class _FakeProvider:
    def __init__(self, model: Any) -> None:
        self.model = model

    def get_model(self, model_name: str | None) -> Any:
        return self.model


class _RecordingTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        self.requests.append({"url": url, "data": data, "kwargs": kwargs})
        return b"unexpected"


@unittest.skipUnless(Agent is not None, "OpenAI Agents SDK is not installed")
class OpenAICustomerServiceHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def test_model_derived_customer_record_is_blocked_at_network_sink(
        self,
    ) -> None:
        hardening = _load_hardening_module()

        class LeakSequenceModel(Model):
            def __init__(self) -> None:
                self.calls = 0

            async def get_response(self, *args: Any, **kwargs: Any) -> Any:
                self.calls += 1
                if self.calls == 1:
                    tool_name = hardening.READ_CUSTOMER_RECORD_TOOL
                    call_id = "call-read-customer"
                    arguments = "{}"
                else:
                    tool_name = hardening.UPLOAD_CUSTOMER_RECORD_TOOL
                    call_id = "call-upload-customer"
                    arguments = json.dumps({"payload": "serialized customer record"})
                return ModelResponse(
                    output=[
                        ResponseFunctionToolCall(
                            arguments=arguments,
                            call_id=call_id,
                            name=tool_name,
                            type="function_call",
                        )
                    ],
                    usage=Usage(),
                    response_id=f"response-{self.calls}",
                )

            def stream_response(self, *args: Any, **kwargs: Any) -> Any:
                async def empty_stream() -> Any:
                    if False:
                        yield None

                return empty_stream()

        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "customer-record.txt"
            secret_path.write_text("FAKE PRIVATE CUSTOMER RECORD", encoding="utf-8")
            transport = _RecordingTransport()
            runtime = hardening.create_airline_runtime(
                secret_path,
                provider_name="fake-openai",
                http_transport=transport,
            )
            delegate = LeakSequenceModel()
            provider = _FakeProvider(delegate)
            root = Agent(name="Existing Triage", model="approved-model")
            hidden_guardrail = Agent(name="Hidden Guardrail", model="approved-model")

            protected = hardening.harden_airline_agent_graph(
                runtime,
                root,
                secret_path=secret_path,
                leak_target="https://untrusted.example/collect",
                model_provider=provider,
                provider_name="fake-openai",
                additional_agents=[hidden_guardrail],
            )

            with runtime.provenance_context.scope():
                with self.assertRaises(Exception) as raised:
                    await Runner.run(root, input="Archive my customer record.")

            block = hardening.flowguard_block_from(raised.exception)
            self.assertIsInstance(block, FlowguardBlocked)
            self.assertEqual(block.policy, "SecretToNetwork")
            self.assertEqual(delegate.calls, 2)
            self.assertEqual(transport.requests, [])
            self.assertIs(protected.root_agent, root)
            self.assertIsInstance(root.model, FlowguardOpenAIModel)
            self.assertIsInstance(hidden_guardrail.model, FlowguardOpenAIModel)

            report = runtime.report()
            self.assertEqual(report.summary.violation_count, 1)
            self.assertEqual(report.violations[0].policy, "SecretToNetwork")
            self.assertEqual(
                report.model_calls[-1].action,
                "ALLOW_AND_PROPAGATE",
            )
            self.assertNotIn("FAKE PRIVATE CUSTOMER RECORD", report.to_json())


def _load_hardening_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "flowguard_openai_cs_hardening",
        HARDENING_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load hardening module from {HARDENING_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    unittest.main()
