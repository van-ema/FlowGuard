from __future__ import annotations

import unittest
from typing import Any

from flowguard import (
    FlowguardBlocked,
    FlowguardRuntime,
    ModelDestination,
    ModelEgressPolicy,
    ModelRule,
    Provenance,
    SourceRef,
)
from flowguard.adapters.openai_model import FlowguardOpenAIModel
from flowguard.tracked import track_value


class FakeModel:
    def __init__(self, response: Any = None, stream_events: list[Any] | None = None) -> None:
        self.response = response or {
            "response_id": "resp-1",
            "output": [],
        }
        self.stream_events = stream_events or []
        self.response_calls = 0
        self.stream_calls = 0
        self.closed = False
        self.cleaned_owner: object | None = None

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        self.response_calls += 1
        return self.response

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        self.stream_calls += 1

        async def stream() -> Any:
            for event in self.stream_events:
                yield event

        return stream()

    async def close(self) -> None:
        self.closed = True

    async def _cleanup_on_run_end(self, owner: object) -> None:
        self.cleaned_owner = owner

    def get_retry_advice(self, request: Any) -> str:
        return "delegate-advice"


class FakeProvider:
    def __init__(self, model: FakeModel) -> None:
        self.model = model
        self.requested_names: list[str | None] = []
        self.closed = False

    def get_model(self, model_name: str | None) -> FakeModel:
        self.requested_names.append(model_name)
        return self.model

    async def aclose(self) -> None:
        self.closed = True


def secret_value() -> Any:
    provenance = Provenance.from_source(
        "Secret",
        SourceRef.file("/secrets/id_rsa"),
    )
    return track_value("PRIVATE KEY", provenance)


async def get_response(model: FlowguardOpenAIModel, input: Any, **state: Any) -> Any:
    return await model.get_response(
        None,
        input,
        object(),
        [],
        None,
        [],
        object(),
        previous_response_id=state.get("previous_response_id"),
        conversation_id=state.get("conversation_id"),
        prompt=None,
    )


class OpenAIModelGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_sensitive_external_request_blocks_before_delegate(self) -> None:
        runtime = FlowguardRuntime()
        delegate = FakeModel()
        model = FlowguardOpenAIModel(
            runtime,
            delegate,
            ModelDestination("openai", "gpt-test", "external"),
        )

        with self.assertRaises(FlowguardBlocked) as raised:
            await get_response(model, secret_value())

        self.assertEqual(raised.exception.policy, "SecretToModel")
        self.assertEqual(delegate.response_calls, 0)

    async def test_sensitive_stored_prompt_blocks_before_delegate(self) -> None:
        runtime = FlowguardRuntime()
        delegate = FakeModel()
        model = FlowguardOpenAIModel(
            runtime,
            delegate,
            ModelDestination("openai", "gpt-test", "external"),
        )

        with self.assertRaises(FlowguardBlocked):
            await model.get_response(
                None,
                "public input",
                object(),
                [],
                None,
                [],
                object(),
                previous_response_id=None,
                conversation_id=None,
                prompt={"variables": {"private_context": secret_value()}},
            )

        self.assertEqual(delegate.response_calls, 0)

    async def test_public_request_is_delegated_and_response_is_known(self) -> None:
        runtime = FlowguardRuntime(precision_mode="strict")
        delegate = FakeModel()
        model = FlowguardOpenAIModel(
            runtime,
            delegate,
            ModelDestination("openai", "gpt-test", "external"),
        )

        response = await get_response(model, "public")
        follow_up = await get_response(
            model,
            "public follow-up",
            previous_response_id="resp-1",
        )

        self.assertEqual(response["response_id"], "resp-1")
        self.assertEqual(follow_up["response_id"], "resp-1")
        self.assertEqual(delegate.response_calls, 2)

    async def test_approved_request_labels_generated_tool_call(self) -> None:
        runtime = FlowguardRuntime(
            model_policy=ModelEgressPolicy(
                [
                    ModelRule.allow_and_propagate(
                        labels={"Secret"},
                        destinations={"model:ollama:*:local"},
                    )
                ]
            )
        )
        delegate = FakeModel(
            {
                "response_id": "resp-sensitive",
                "output": [
                    {
                        "type": "function_call",
                        "call_id": "call-send",
                        "arguments": '{"payload":"serialized"}',
                    }
                ],
            }
        )
        model = FlowguardOpenAIModel(
            runtime,
            delegate,
            ModelDestination("ollama", "llama", "local"),
        )

        await get_response(model, secret_value())

        call_provenance = runtime.provenance_context.provenance_for_tool_call(
            "call-send"
        )
        self.assertTrue(call_provenance.has_label("Secret"))
        self.assertIn(
            "model_output_labeled",
            [event["type"] for event in runtime.emitter.events],
        )

    async def test_unknown_previous_response_blocks_in_strict_mode(self) -> None:
        runtime = FlowguardRuntime(precision_mode="strict")
        delegate = FakeModel()
        model = FlowguardOpenAIModel(
            runtime,
            delegate,
            ModelDestination("openai", "gpt-test", "external"),
        )

        with self.assertRaises(FlowguardBlocked) as raised:
            await get_response(
                model,
                "public delta",
                previous_response_id="resp-unknown",
            )

        self.assertEqual(raised.exception.policy, "UntrackedModelContext")
        self.assertEqual(delegate.response_calls, 0)

    async def test_sensitive_stream_blocks_before_stream_is_opened(self) -> None:
        runtime = FlowguardRuntime()
        delegate = FakeModel(stream_events=[{"type": "response.completed"}])
        model = FlowguardOpenAIModel(
            runtime,
            delegate,
            ModelDestination("openai", "gpt-test", "external"),
        )

        with self.assertRaises(FlowguardBlocked):
            async for _ in model.stream_response(
                None,
                secret_value(),
                object(),
                [],
                None,
                [],
                object(),
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ):
                pass

        self.assertEqual(delegate.stream_calls, 0)

    async def test_provider_and_lifecycle_delegate(self) -> None:
        runtime = FlowguardRuntime()
        delegate_model = FakeModel()
        delegate_provider = FakeProvider(delegate_model)
        provider = runtime.openai_model_provider(
            delegate_provider,
            provider_name="test-provider",
        )

        model = provider.get_model("test-model")
        await get_response(model, "public")
        owner = object()
        await model._cleanup_on_run_end(owner)
        await model.close()
        await provider.aclose()

        self.assertEqual(delegate_provider.requested_names, ["test-model"])
        self.assertEqual(model.get_retry_advice(object()), "delegate-advice")
        self.assertIs(delegate_model.cleaned_owner, owner)
        self.assertTrue(delegate_model.closed)
        self.assertTrue(delegate_provider.closed)


if __name__ == "__main__":
    unittest.main()
