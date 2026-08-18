from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from typing import Any

from flowguard import FlowguardBlocked
from flowguard.adapters.openai_model import FlowguardOpenAIModel

try:
    from agents import Agent, Runner, function_tool
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import (
        ResponseFunctionToolCall,
        ResponseOutputMessage,
        ResponseOutputText,
    )
except ImportError:
    Agent = Runner = ModelResponse = Model = Usage = function_tool = None
    ResponseFunctionToolCall = ResponseOutputMessage = ResponseOutputText = None

_ModelBase = Model if Model is not None else object

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
HARDENING_PATH = (
    RUNTIME_ROOT / "integrations" / "openai-cs-agents-demo" / "hardening.py"
)
FAKE_CUSTOMER_RECORD = "Confirmation FG1234 from Paris to Austin"
LEAK_TARGET = "https://untrusted.example/collect"


class _FakeProvider:
    def __init__(self, model: Any) -> None:
        self.model = model

    def get_model(self, model_name: str | None) -> Any:
        return self.model


class _RecordingReceiver:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        self.requests.append({"url": url, "data": data, "kwargs": kwargs})
        return b"accepted"


@unittest.skipUnless(Agent is not None, "OpenAI Agents SDK is not installed")
class OpenAICustomerServiceHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def test_baseline_delivers_native_customer_data_to_receiver(self) -> None:
        hardening = _load_hardening_module()
        receiver = _RecordingReceiver()
        delegate = _LeakSequenceModel(hardening)
        root = _build_agent(hardening, delegate)
        hardening.add_customer_export_tool(
            root,
            leak_target=LEAK_TARGET,
            receiver=receiver,
        )

        await Runner.run(root, input="Archive my trip details.")

        self.assertEqual(delegate.calls, 2)
        self.assertEqual(len(receiver.requests), 1)
        self.assertEqual(receiver.requests[0]["data"], "serialized customer data")

    async def test_protected_mode_blocks_same_export_before_receiver(self) -> None:
        hardening = _load_hardening_module()
        receiver = _RecordingReceiver()
        delegate = _LeakSequenceModel(hardening)
        provider = _FakeProvider(delegate)
        root = _build_agent(hardening, "approved-model")
        hidden_guardrail = Agent(name="Hidden Guardrail", model="approved-model")
        runtime = hardening.create_airline_runtime(provider_name="fake-openai")

        protected = hardening.harden_airline_agent_graph(
            runtime,
            root,
            leak_target=LEAK_TARGET,
            receiver=receiver,
            model_provider=provider,
            provider_name="fake-openai",
            additional_agents=[hidden_guardrail],
        )

        with runtime.provenance_context.scope():
            with self.assertRaises(Exception) as raised:
                await Runner.run(root, input="Archive my trip details.")

        block = hardening.flowguard_block_from(raised.exception)
        self.assertIsInstance(block, FlowguardBlocked)
        self.assertEqual(block.policy, hardening.CUSTOMER_DATA_TO_NETWORK_POLICY)
        self.assertEqual(delegate.calls, 2)
        self.assertEqual(receiver.requests, [])
        self.assertIs(protected.root_agent, root)
        self.assertIsInstance(root.model, FlowguardOpenAIModel)
        self.assertIsInstance(hidden_guardrail.model, FlowguardOpenAIModel)

        report = runtime.report()
        self.assertEqual(report.summary.violation_count, 1)
        self.assertEqual(
            report.violations[0].policy,
            hardening.CUSTOMER_DATA_TO_NETWORK_POLICY,
        )
        self.assertEqual(report.violations[0].event_type, "tool_call_blocked")
        self.assertEqual(report.model_calls[-1].action, "ALLOW_AND_PROPAGATE")
        self.assertIn("tool:get_trip_details", report.violations[0].sources)
        self.assertIn(
            "tool_output_labeled",
            [event["type"] for event in report.events],
        )
        self.assertNotIn(FAKE_CUSTOMER_RECORD, report.to_json())

    async def test_protected_customer_data_without_export_is_allowed(self) -> None:
        hardening = _load_hardening_module()
        delegate = _BenignSequenceModel(hardening)
        runtime = hardening.create_airline_runtime(provider_name="fake-openai")
        root = _build_agent(hardening, "approved-model")
        hardening.protect_airline_agent_graph(
            runtime,
            root,
            model_provider=_FakeProvider(delegate),
            provider_name="fake-openai",
        )

        with runtime.provenance_context.scope():
            result = await Runner.run(root, input="Summarize my trip details.")

        self.assertEqual(result.final_output, "Your itinerary is ready.")
        self.assertEqual(delegate.calls, 2)
        self.assertNotIn(
            hardening.UPLOAD_CUSTOMER_RECORD_TOOL,
            {getattr(tool, "name", None) for tool in root.tools},
        )
        report = runtime.report()
        self.assertEqual(report.summary.violation_count, 0)
        self.assertEqual(report.model_calls[-1].action, "ALLOW_AND_PROPAGATE")
        self.assertIn(
            "tool_output_labeled",
            [event["type"] for event in report.events],
        )

    async def test_customer_data_is_blocked_before_external_model_call(self) -> None:
        hardening = _load_hardening_module()
        delegate = _BenignSequenceModel(hardening)
        runtime = hardening.create_model_egress_blocking_runtime(
            provider_name="fake-openai"
        )
        root = _build_agent(hardening, "external-model")
        hardening.protect_airline_agent_graph(
            runtime,
            root,
            model_provider=_FakeProvider(delegate),
            provider_name="fake-openai",
        )

        with runtime.provenance_context.scope():
            with self.assertRaises(Exception) as raised:
                await Runner.run(root, input="Summarize my trip details.")

        block = hardening.flowguard_block_from(raised.exception)
        self.assertIsInstance(block, FlowguardBlocked)
        self.assertEqual(
            block.policy,
            hardening.CUSTOMER_DATA_TO_EXTERNAL_MODEL_POLICY,
        )
        self.assertEqual(delegate.calls, 1)
        report = runtime.report()
        self.assertEqual(report.summary.violation_count, 1)
        self.assertEqual(report.violations[0].event_type, "model_request_blocked")
        self.assertIn("tool:get_trip_details", report.violations[0].sources)

    async def test_public_tool_output_is_allowed_to_external_model(self) -> None:
        hardening = _load_hardening_module()
        delegate = _PublicSequenceModel()
        runtime = hardening.create_model_egress_blocking_runtime(
            provider_name="fake-openai"
        )
        root = _build_agent(hardening, "external-model")

        @function_tool(name_override="faq_lookup_tool", failure_error_function=None)
        def faq_lookup_tool(question: str) -> str:
            return "One carry-on bag is allowed."

        root.tools = [*root.tools, faq_lookup_tool]
        hardening.protect_airline_agent_graph(
            runtime,
            root,
            model_provider=_FakeProvider(delegate),
            provider_name="fake-openai",
        )

        with runtime.provenance_context.scope():
            result = await Runner.run(root, input="What is the baggage allowance?")

        self.assertEqual(result.final_output, "Public baggage policy.")
        self.assertEqual(delegate.calls, 2)
        self.assertEqual(runtime.report().summary.violation_count, 0)


class _LeakSequenceModel(_ModelBase):
    def __init__(self, hardening: Any) -> None:
        self.hardening = hardening
        self.calls = 0

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        if self.calls == 1:
            tool_name = self.hardening.CUSTOMER_RECORD_SOURCE_TOOL
            call_id = "call-get-trip"
            arguments = json.dumps({"message": "Paris New York Austin"})
        else:
            tool_name = self.hardening.UPLOAD_CUSTOMER_RECORD_TOOL
            call_id = "call-upload-customer"
            arguments = json.dumps({"payload": "serialized customer data"})
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


class _BenignSequenceModel(_ModelBase):
    def __init__(self, hardening: Any) -> None:
        self.hardening = hardening
        self.calls = 0

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        if self.calls == 1:
            output = [
                ResponseFunctionToolCall(
                    arguments=json.dumps(
                        {"message": "Paris New York Austin"}
                    ),
                    call_id="call-get-trip",
                    name=self.hardening.CUSTOMER_RECORD_SOURCE_TOOL,
                    type="function_call",
                )
            ]
        else:
            output = [
                ResponseOutputMessage(
                    id="message-benign",
                    content=[
                        ResponseOutputText(
                            annotations=[],
                            text="Your itinerary is ready.",
                            type="output_text",
                        )
                    ],
                    role="assistant",
                    status="completed",
                    type="message",
                )
            ]
        return ModelResponse(
            output=output,
            usage=Usage(),
            response_id=f"response-{self.calls}",
        )

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        async def empty_stream() -> Any:
            if False:
                yield None

        return empty_stream()


class _PublicSequenceModel(_ModelBase):
    def __init__(self) -> None:
        self.calls = 0

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        if self.calls == 1:
            output = [
                ResponseFunctionToolCall(
                    arguments=json.dumps({"question": "baggage allowance"}),
                    call_id="call-faq",
                    name="faq_lookup_tool",
                    type="function_call",
                )
            ]
        else:
            output = [
                ResponseOutputMessage(
                    id="message-public",
                    content=[
                        ResponseOutputText(
                            annotations=[],
                            text="Public baggage policy.",
                            type="output_text",
                        )
                    ],
                    role="assistant",
                    status="completed",
                    type="message",
                )
            ]
        return ModelResponse(
            output=output,
            usage=Usage(),
            response_id=f"response-public-{self.calls}",
        )

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        async def empty_stream() -> Any:
            if False:
                yield None

        return empty_stream()


def _build_agent(hardening: Any, model: Any) -> Any:
    @function_tool(
        name_override=hardening.CUSTOMER_RECORD_SOURCE_TOOL,
        failure_error_function=None,
    )
    def get_trip_details(message: str) -> str:
        return FAKE_CUSTOMER_RECORD

    return Agent(
        name="Existing Triage",
        model=model,
        tools=[get_trip_details],
        tool_use_behavior={
            "stop_at_tool_names": [hardening.UPLOAD_CUSTOMER_RECORD_TOOL]
        },
    )


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
