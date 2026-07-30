# Model Request Guard

Status: Implemented

## Summary

The Model Request Guard treats every model invocation as a data-egress boundary.

A hosted model call sends system instructions, conversation history, user input,
tool results, attachments, and other context to a remote provider. If any of that
data is secret-derived, the request is a potential disclosure even when the
model never calls another tool.

The guard makes a provenance-aware policy decision before the model transport is
opened:

```text
sensitive source
-> agent value or tool result
-> model request
-> model-egress policy
-> block or approved disclosure
-> model provider
```

When an approved model is allowed to receive sensitive data, the guard
conservatively propagates that provenance to the model response and generated
tool calls:

```text
sensitive model input
-> approved model
-> model response or generated tool arguments
-> inherited sensitive provenance
-> later sink policy
```

This feature closes two gaps:

1. Sensitive data can currently reach a model provider before normal tool or
   HTTP-sink policy runs.
2. Python provenance objects do not survive framework JSON serialization and a
   model round trip.

## Security Goal

The feature enforces this invariant:

> Sensitive data does not enter a model destination without an explicit policy
> decision, and approved model processing does not silently erase provenance.

The first implementation provides two sensitive-data outcomes:

- `BLOCK`: stop before the model provider receives a request.
- `ALLOW_AND_PROPAGATE`: allow the approved disclosure and apply the request
  provenance to the model response and generated tool calls.

Requests without sensitive provenance are allowed under the normal destination
policy.

## Threat Model

The Model Request Guard assumes:

- the model may be remote and operated by another organization;
- prompts and tool results may contain secrets, credentials, PII, customer
  records, source code, or other restricted data;
- the model may reproduce, summarize, encode, transform, or place sensitive data
  in generated tool arguments;
- agent frameworks serialize Python values into provider request formats;
- serialization removes `TrackedStr` and `TrackedBytes` runtime identity;
- server-managed conversation state may omit prior context from later request
  payloads;
- model calls may use HTTP or WebSocket transport;
- multiple agent runs may execute concurrently in one Python process.

The guard does not assume that a model provider, model output, or generated tool
call is trustworthy.

## Non-Goals

The first implementation does not:

- classify prompt text by inspecting secret-like patterns;
- prove which exact output tokens depend on which input tokens;
- sanitize or redact arbitrary sensitive content;
- implement human approval workflows;
- replace container or operating-system network containment;
- prevent raw sockets, native clients, or subprocesses from bypassing Python;
- support every agent framework in the first change;
- declassify model output automatically.

Those capabilities build on this feature but are not required to establish the
model boundary.

## Model Destination

A model destination is a policy identity, not only a URL.

```python
@dataclass(frozen=True, slots=True)
class ModelDestination:
    provider: str
    model: str
    trust_zone: str
```

Initial trust zones:

- `external`: a hosted provider outside the protected environment;
- `enterprise`: an explicitly approved hosted deployment;
- `local`: a model running inside the protected environment.

Example identities:

```text
model:openai:gpt-5:external
model:openai-enterprise:gpt-5:enterprise
model:ollama:llama:local
```

The adapter constructs the destination from trusted configuration. Model output
or agent-generated text cannot choose or override its own destination identity.

## Policy Semantics

The initial policy matrix is:

```text
Public -> approved model destination       ALLOW
Secret -> external model destination       BLOCK
Secret -> approved enterprise destination ALLOW_AND_PROPAGATE
Secret -> approved local destination      ALLOW_AND_PROPAGATE
Unknown provenance -> strict mode         BLOCK
```

Additional labels such as `PII`, `CustomerData`, `Credential`, and
`UntrustedInput` use the same mechanism.

Example policy:

```python
ModelRule.block(
    labels={"Secret", "Credential"},
    destinations={"model:*:*:external"},
)

ModelRule.allow_and_propagate(
    labels={"PII"},
    destinations={"model:openai-enterprise:*:enterprise"},
)

ModelRule.allow_and_propagate(
    labels={"Secret", "Credential", "PII"},
    destinations={"model:ollama:*:local"},
)
```

`ALLOW_AND_PROPAGATE` is an approved disclosure, not declassification. The
provenance remains active after the model call.

## Enforcement Flow

### Blocked External Model Request

```text
file:/secrets/id_rsa
-> read_secret tool result
-> OpenAI model input
-> SecretToModel
-> blocked before provider transport
```

Expected result:

```text
policy: SecretToModel
provider_calls: 0
```

### Approved Local Model Request

```text
file:/secrets/id_rsa
-> local model input
-> ALLOW_AND_PROPAGATE
-> local model output
-> generated send_report arguments
-> external HTTP sink
-> SecretToNetwork
-> blocked before network transport
```

The model may transform or omit the secret. Without exact model attribution,
all response items from a sensitive request conservatively inherit the merged
request provenance.

## Core Architecture

```text
Agent framework
-> Flowguard framework adapter
-> guarded model/model provider
-> request provenance resolver
-> model-egress policy
-> provider transport
-> response provenance binder
-> framework tool dispatcher
-> guarded tool and sink policy
```

The core policy and provenance state are framework-neutral. Framework adapters
map SDK-specific request items, response IDs, conversation IDs, and tool-call
IDs into the core.

## Sidecar Provenance

Runtime subclasses are insufficient across model calls:

```text
TrackedStr
-> JSON encoding
-> provider request
-> provider response
-> JSON decoding
-> plain str
```

The feature uses sidecar provenance keyed by stable framework identifiers:

```text
tool_call_id      -> tool output provenance
model_request_id  -> merged request provenance
response_id       -> model response provenance
generated call_id -> generated tool-call provenance
conversation_id   -> cumulative conversation provenance
```

The registry exposes operations equivalent to:

```python
bind_tool_output(tool_call_id, provenance)
provenance_for_model_input(input_items)
bind_model_response(response_id, provenance)
bind_generated_tool_call(tool_call_id, provenance)
provenance_for_tool_call(tool_call_id)
```

The registry uses `contextvars` or another async-safe run scope. It is not a
single mutable process-global dictionary. Provenance from concurrent agent runs
must never mix.

## Tool Output Binding

After a protected tool returns, the framework adapter binds its result
provenance to the framework tool-call ID:

```text
tool_call_id: call-read-1
labels: [Secret]
sources: [file:/secrets/id_rsa]
```

When the framework prepares the next model request, the request provenance
resolver matches the `function_call_output` item to `call-read-1`. The decision
does not depend on recovering provenance from serialized secret text.

## Model Response Binding

For `ALLOW_AND_PROPAGATE`, the guard binds the merged request provenance to:

- the model response ID;
- response message items;
- generated function/tool call IDs;
- provider-managed conversation state known to the runtime.

Before a generated tool executes, the framework adapter resolves the call ID
and activates its provenance. The first implementation conservatively applies
that provenance to string, bytes, and structured arguments for the call.

Field-level output attribution is a later precision improvement.

## OpenAI Agents SDK Integration

The first framework implementation wraps the OpenAI Agents SDK model
abstraction rather than patching its HTTP client.

The SDK model abstraction has two relevant operations:

- `get_response(...)`;
- `stream_response(...)`.

A guarded model delegates to the real model only after policy allows the
request:

```python
class FlowguardOpenAIModel:
    async def get_response(self, ..., input, ...):
        provenance = self._resolver.for_model_input(input)
        decision = self._runtime.check_model_egress(
            self._destination,
            provenance,
        )

        if decision.blocked:
            raise FlowguardBlocked(decision)

        response = await self._delegate.get_response(...)
        self._registry.bind_model_response(
            response,
            provenance=decision.output_provenance,
        )
        return response
```

A guarded model provider wraps model-name resolution so existing agents can
continue using normal model names:

```python
run_config = RunConfig(
    model_provider=runtime.openai_model_provider(provider),
)
```

OpenAI lifecycle or tool-context integration supplies stable `tool_call_id`
values for tool result and generated argument binding.

The core remains independent of the optional `openai-agents` dependency.
Imports remain lazy inside the adapter.

## Streaming

Streaming cannot bypass the preflight policy.

The guard:

1. resolves input provenance;
2. emits `model_request_attempt`;
3. evaluates policy;
4. blocks before opening HTTP or WebSocket transport when denied;
5. delegates only when allowed;
6. observes stream events and binds final response and generated tool-call IDs.

Until response and generated-call binding is implemented and tested, strict
mode rejects sensitive `ALLOW_AND_PROPAGATE` streaming calls. Public streaming
requests remain allowed.

## Server-Managed Conversation State

`conversation_id` and `previous_response_id` may cause a provider request to
contain only the current delta rather than full prior context.

The guard therefore tracks cumulative provenance:

```text
conversation provenance =
    prior conversation provenance
    + current request provenance
```

Rules:

- a known response or conversation ID inherits its recorded provenance;
- a new tool result adds provenance to the next model request;
- a known conversation accumulates sensitive labels and sources;
- an unknown server-managed context is not considered public;
- strict mode blocks unknown context as `UntrackedModelContext`.

The absence of sensitive text from a request delta is not proof that the
provider conversation is untainted.

## Decisions

The feature adds:

```text
SecretToModel
UntrackedModelContext
```

`SecretToModel` contains:

- decision kind;
- policy name;
- model destination;
- labels;
- source references;
- explanation;
- run and event sequence;
- no sensitive content.

Example explanation:

```text
Secret-derived data from file:/secrets/id_rsa would enter external model
openai/gpt-5.
```

## Events

The runtime emits:

```text
model_request_attempt
model_request_allowed
model_request_blocked
model_response_received
model_output_labeled
```

Common fields:

```text
run_id
request_sequence
provider
model
trust_zone
transport
labels
sources
policy
action
response_id
conversation_id
```

Reports never include raw prompts, tool outputs, model responses, API keys, or
secret values. Optional hashes and lengths may identify repeated artifacts
without storing their contents.

## Report Example

```json
{
  "event_type": "model_request_blocked",
  "policy": "SecretToModel",
  "destination": "model:openai:gpt-5:external",
  "labels": ["Secret"],
  "sources": ["file:/secrets/id_rsa"],
  "explanation": "Secret-derived data would enter an external model",
  "provider_calls": 0
}
```

The final causal explanation is:

```text
file:/secrets/id_rsa
-> read_secret
-> tool output call-read-1
-> model request openai/gpt-5
-> blocked SecretToModel
```

For approved model processing:

```text
file:/secrets/id_rsa
-> approved local model
-> generated call-send-1
-> send_report payload
-> blocked SecretToNetwork
```

## Proposed Module Layout

```text
runtimes/python-taint/src/flowguard/
  model.py
  provenance_context.py
  decisions.py
  runtime.py
  report.py
  adapters/
    openai_model.py
    openai_agents.py

runtimes/python-taint/tests/
  test_model_policy.py
  test_provenance_context.py
  test_openai_model_guard.py
  test_openai_model_roundtrip.py
```

Responsibilities:

- `model.py`: model destinations, actions, rules, and framework-neutral
  decisions;
- `provenance_context.py`: async-safe sidecar bindings;
- `runtime.py`: model-egress policy entry point;
- `decisions.py`: `SecretToModel` and unknown-context decisions;
- `report.py`: model-call summaries and violations;
- `adapters/openai_model.py`: guarded model and model-provider wrappers;
- `adapters/openai_agents.py`: tool-call ID integration and argument
  provenance activation.

## Implementation Sequence

### 1. Core Policy

- add model destination and action types;
- add a default deny rule for sensitive data to external models;
- add `FlowguardRuntime.check_model_egress`;
- add `SecretToModel`;
- test public, blocked, and approved destinations.

### 2. Sidecar Registry

- add run-scoped provenance bindings;
- bind and resolve tool-call, response, and conversation IDs;
- test nested scopes and concurrent async runs;
- test that completed runs release their state.

### 3. Events and Reports

- emit attempt, allow, block, response, and propagation events;
- add blocked model requests to report violations;
- add model-call summaries;
- prove reports contain no raw sensitive content.

### 4. OpenAI Guarded Model

- lazily wrap a concrete SDK model;
- wrap model-provider lookup;
- enforce non-streaming requests before delegation;
- bind response and generated call provenance;
- delegate model close/resource management.

### 5. Tool Round-Trip Integration

- bind protected tool output to `tool_call_id`;
- resolve tool output provenance in the next model request;
- bind generated call IDs to approved model-request provenance;
- reactivate provenance before tool execution.

### 6. Stateful and Streaming Support

- enforce before opening streaming transport;
- bind stream response and generated call IDs;
- track known `response_id` and `conversation_id` provenance;
- fail closed for unknown sensitive or untracked state.

### 7. Demonstration and Documentation

- add a deterministic fake-model regression;
- add an optional live OpenAI demo;
- update the README with policy behavior and report paths;
- document that operating-system egress containment remains a separate layer.

## Required Regressions

### External Model Block

```text
turn 1: model requests read_secret
tool: read_secret returns Secret
turn 2: SDK prepares tool output for model
guard: SecretToModel blocks
```

Assertions:

```text
first model calls: 1
second provider calls: 0
policy: SecretToModel
secret in reports: false
```

### Approved Model Propagation

```text
read_secret
-> approved local model
-> generated send_report call
-> reactivated Secret provenance
-> SecretToNetwork
```

Assertions:

```text
model call: allowed
generated call provenance: Secret
network calls: 0
policy: SecretToNetwork
```

### Public Request

```text
constant public input
-> approved external model
-> allowed
```

Assertions:

```text
provider calls: 1
model_request_allowed: present
violations: 0
```

### Isolation

Two concurrent runs use different secret sources and call IDs.

Assertions:

```text
run A report contains only source A
run B report contains only source B
no cross-run labels or IDs
```

### Unknown Conversation

An agent supplies an unknown `conversation_id` in strict mode.

Assertions:

```text
provider calls: 0
policy: UntrackedModelContext
```

### Streaming Block

A sensitive external streaming request is attempted.

Assertions:

```text
stream transport opened: false
events yielded: 0
policy: SecretToModel
```

## Acceptance Criteria

The feature is complete when:

- model requests are inspected before provider transport;
- secret-derived external requests are blocked by default;
- blocked requests produce zero provider calls;
- approved sensitive requests preserve provenance across model responses and
  generated tool calls;
- tool-call and conversation bindings survive framework serialization;
- concurrent runs remain isolated;
- non-streaming and streaming paths fail closed;
- unknown server-managed context fails closed in strict mode;
- reports explain source-to-model and model-to-tool paths;
- reports contain no secret plaintext;
- the OpenAI Agents SDK remains an optional dependency;
- existing Python taint and system-provenance regressions continue to pass.

The public demonstration claim becomes:

```text
A real agent read a secret. Flowguard intercepted the next model request,
blocked SecretToModel before provider transport, and recorded an explainable
source-to-model path without storing the secret.
```

## Relationship to the Egress Broker

The Model Request Guard protects model calls made through supported framework
adapters. It does not alone enforce the complete `No untracked egress`
invariant.

The subsequent egress-broker milestone removes unrestricted network access from
the agent worker and routes approved model and HTTP traffic through
Flowguard-controlled transports. That layer blocks raw sockets, native clients,
subprocesses, and malicious code that bypass Python adapters.

Together:

```text
Model Request Guard = precise model-boundary decision
Egress Broker       = containment against bypass
```

## References

- OpenAI Agents SDK model interface:
  <https://openai.github.io/openai-agents-python/ref/models/interface/>
- OpenAI Agents SDK model configuration:
  <https://openai.github.io/openai-agents-python/models/>
- OpenAI Agents SDK lifecycle hooks:
  <https://openai.github.io/openai-agents-python/ref/lifecycle/>
- OpenAI Agents SDK tool context:
  <https://openai.github.io/openai-agents-python/context/>
