from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from flowguard import FlowguardBlocked, FlowguardRuntime
from flowguard.adapters.openai_model import FlowguardOpenAIModel

try:
    from agents import Agent, Runner, function_tool, handoff
    from agents.items import ModelResponse
    from agents.models.interface import Model
    from agents.usage import Usage
    from openai.types.responses import ResponseFunctionToolCall
except ImportError:
    Agent = Runner = ModelResponse = Model = Usage = None
    ResponseFunctionToolCall = function_tool = handoff = None


class _FakeProvider:
    def __init__(self, models: dict[str | None, Any]) -> None:
        self.models = models
        self.requested_names: list[str | None] = []

    def get_model(self, model_name: str | None) -> Any:
        self.requested_names.append(model_name)
        return self.models[model_name]


@unittest.skipUnless(Agent is not None, "OpenAI Agents SDK is not installed")
class OpenAIAgentGraphTests(unittest.IsolatedAsyncioTestCase):
    async def test_protects_cyclic_graph_and_preserves_function_tool_schema(self) -> None:
        class StaticModel(Model):
            async def get_response(self, *args: Any, **kwargs: Any) -> Any:
                return ModelResponse(output=[], usage=Usage(), response_id=None)

            def stream_response(self, *args: Any, **kwargs: Any) -> Any:
                async def empty_stream() -> Any:
                    if False:
                        yield None

                return empty_stream()

        @function_tool(
            name_override="lookup_trip",
            description_override="Look up a trip without changing it.",
        )
        async def lookup_trip(confirmation: str) -> str:
            return confirmation

        original_tool = lookup_trip
        original_schema = lookup_trip.params_json_schema
        root = Agent(name="Triage", model="triage-model", tools=[lookup_trip])
        child = Agent(name="Booking", model="booking-model")
        guardrail = Agent(name="Guardrail", model="guardrail-model")
        root.handoffs = [handoff(child)]
        child.handoffs = [root]

        provider = _FakeProvider(
            {
                "triage-model": StaticModel(),
                "booking-model": StaticModel(),
                "guardrail-model": StaticModel(),
            }
        )
        runtime = FlowguardRuntime()

        protected = runtime.protect_openai_agent_graph(
            root,
            model_provider=provider,
            provider_name="fake-openai",
            additional_agents=[guardrail],
        )

        self.assertIs(protected, root)
        self.assertIsInstance(root.model, FlowguardOpenAIModel)
        self.assertIsInstance(child.model, FlowguardOpenAIModel)
        self.assertIsInstance(guardrail.model, FlowguardOpenAIModel)
        self.assertEqual(
            provider.requested_names,
            ["triage-model", "booking-model", "guardrail-model"],
        )

        protected_tool = root.tools[0]
        self.assertIsNot(protected_tool, original_tool)
        self.assertEqual(protected_tool.name, original_tool.name)
        self.assertEqual(protected_tool.description, original_tool.description)
        self.assertEqual(protected_tool.params_json_schema, original_schema)
        self.assertEqual(
            protected_tool.strict_json_schema,
            original_tool.strict_json_schema,
        )
        self.assertEqual(protected_tool.is_enabled, original_tool.is_enabled)
        self.assertEqual(protected_tool.needs_approval, original_tool.needs_approval)

        runtime.protect_openai_agent_graph(
            root,
            model_provider=provider,
            provider_name="fake-openai",
            additional_agents=[guardrail],
        )
        self.assertEqual(len(provider.requested_names), 3)
        self.assertIs(root.tools[0], protected_tool)

    async def test_existing_function_tool_keeps_provenance_for_next_model_call(
        self,
    ) -> None:
        class ReadSecretModel(Model):
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

            @function_tool(failure_error_function=None)
            def read_secret(path: str) -> str:
                # Existing SDK tools use normal IO; graph protection patches it.
                with open(path, encoding="utf-8") as handle:
                    return handle.read()

            delegate = ReadSecretModel()
            provider = _FakeProvider({"fake-model": delegate})
            agent = Agent(
                name="Existing agent",
                model="fake-model",
                tools=[read_secret],
            )
            runtime.protect_openai_agent_graph(
                agent,
                model_provider=provider,
                provider_name="fake-openai",
            )

            with self.assertRaises(FlowguardBlocked) as raised:
                await Runner.run(agent, input="Read the configured file.")

            self.assertEqual(raised.exception.policy, "SecretToModel")
            self.assertEqual(delegate.calls, 1)
            self.assertTrue(
                runtime.provenance_context.provenance_for_model_input(
                    [
                        {
                            "type": "function_call_output",
                            "call_id": "call-read-secret",
                            "output": "serialized",
                        }
                    ]
                ).provenance.has_label("Secret")
            )


if __name__ == "__main__":
    unittest.main()
