from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from ..model import ModelDestination, ModelEgressAction, ModelPolicyResult
from ..provenance import Provenance
from ..provenance_context import ModelBinding

try:
    from agents.models.interface import Model as _SdkModel
    from agents.models.interface import ModelProvider as _SdkModelProvider
except ImportError:

    class _SdkModel:
        pass

    class _SdkModelProvider:
        pass


class FlowguardOpenAIModel(_SdkModel):
    """Enforce Flowguard policy around an OpenAI Agents SDK model."""

    def __init__(
        self,
        runtime: Any,
        delegate: Any,
        destination: ModelDestination,
    ) -> None:
        self._runtime = runtime
        self._delegate = delegate
        self.destination = destination

    async def get_response(
        self,
        system_instructions: Any,
        input: Any,
        model_settings: Any,
        tools: Any,
        output_schema: Any,
        handoffs: Any,
        tracing: Any,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any,
    ) -> Any:
        provenance, result = self._preflight(
            system_instructions,
            input,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
            transport="model",
        )
        response = await self._delegate.get_response(
            system_instructions,
            input,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )
        binding = self._runtime.provenance_context.bind_model_artifacts(
            response,
            provenance,
            conversation_id=conversation_id,
        )
        self._emit_response(binding, provenance, result)
        return response

    def stream_response(
        self,
        system_instructions: Any,
        input: Any,
        model_settings: Any,
        tools: Any,
        output_schema: Any,
        handoffs: Any,
        tracing: Any,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any,
    ) -> AsyncIterator[Any]:
        async def guarded_stream() -> AsyncIterator[Any]:
            provenance, result = self._preflight(
                system_instructions,
                input,
                previous_response_id=previous_response_id,
                conversation_id=conversation_id,
                prompt=prompt,
                transport="stream",
            )
            last_binding = ModelBinding(response_id=None, tool_call_ids=())
            stream = self._delegate.stream_response(
                system_instructions,
                input,
                model_settings,
                tools,
                output_schema,
                handoffs,
                tracing,
                previous_response_id=previous_response_id,
                conversation_id=conversation_id,
                prompt=prompt,
            )
            async for event in stream:
                binding = self._runtime.provenance_context.bind_model_artifacts(
                    event,
                    provenance,
                )
                last_binding = _merge_bindings(last_binding, binding)
                yield event
            if conversation_id:
                self._runtime.provenance_context.bind_conversation(
                    conversation_id,
                    provenance,
                )
            self._emit_response(last_binding, provenance, result)

        return guarded_stream()

    async def close(self) -> None:
        close = getattr(self._delegate, "close", None)
        if close is not None:
            await close()

    async def _cleanup_on_run_end(self, owner: object) -> None:
        cleanup = getattr(self._delegate, "_cleanup_on_run_end", None)
        if cleanup is not None:
            await cleanup(owner)

    def get_retry_advice(self, request: Any) -> Any:
        get_advice = getattr(self._delegate, "get_retry_advice", None)
        if get_advice is None:
            return None
        return get_advice(request)

    def _preflight(
        self,
        system_instructions: Any,
        input: Any,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any,
        transport: str,
    ) -> tuple[Provenance, ModelPolicyResult]:
        resolved = self._runtime.provenance_context.provenance_for_model_input(
            input,
            system_instructions=system_instructions,
            prompt=prompt,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
        )
        result = self._runtime.check_model_egress(
            self.destination,
            resolved.provenance,
            unknown_context_ids=resolved.unknown_context_ids,
            transport=transport,
        )
        return resolved.provenance, result

    def _emit_response(
        self,
        binding: ModelBinding,
        provenance: Provenance,
        result: ModelPolicyResult,
    ) -> None:
        details = {
            "target": self.destination.target,
            "provider": self.destination.provider,
            "model": self.destination.model,
            "trust_zone": self.destination.trust_zone,
            "response_id": binding.response_id,
            "tool_call_ids": list(binding.tool_call_ids),
            "labels": sorted(provenance.labels),
            "sources": [source.display() for source in provenance.sources],
        }
        self._runtime.emitter.emit("model_response_received", **details)
        if result.action is ModelEgressAction.ALLOW_AND_PROPAGATE:
            self._runtime.emitter.emit(
                "model_output_labeled",
                **details,
                policy=result.policy,
                action=result.action.value,
            )


class FlowguardOpenAIModelProvider(_SdkModelProvider):
    """Wrap SDK model lookup so every selected model is guarded."""

    def __init__(
        self,
        runtime: Any,
        delegate: Any,
        *,
        provider_name: str,
        trust_zone: str,
    ) -> None:
        self._runtime = runtime
        self._delegate = delegate
        self._provider_name = provider_name
        self._trust_zone = trust_zone

    def get_model(self, model_name: str | None) -> FlowguardOpenAIModel:
        delegate = self._delegate.get_model(model_name)
        return FlowguardOpenAIModel(
            self._runtime,
            delegate,
            ModelDestination(
                provider=self._provider_name,
                model=model_name or "default",
                trust_zone=self._trust_zone,
            ),
        )

    async def aclose(self) -> None:
        close = getattr(self._delegate, "aclose", None)
        if close is not None:
            await close()


def _merge_bindings(left: ModelBinding, right: ModelBinding) -> ModelBinding:
    return ModelBinding(
        response_id=right.response_id or left.response_id,
        tool_call_ids=tuple(
            dict.fromkeys((*left.tool_call_ids, *right.tool_call_ids))
        ),
    )
