# Python Taint Runtime Demos

Run commands from the repository root. Demo secrets and network destinations
are fake. Reports are content-safe and are written under `logs/` by default.

## Demo Matrix

| Demo | Network/API | What it demonstrates |
| --- | --- | --- |
| Python MVP PoC | Offline | Generated-code taint propagation, a blocked transformed secret, allowed constant telemetry, and strict precision-loss blocking |
| Model Request Guard | Offline | A secret tool result is blocked before the next model-provider request |
| LangChain/LangGraph | Offline | Flowguard tools retain enforcement when adapted to framework tool interfaces |
| Live OpenAI Agent | OpenAI API | A real LLM generates exfiltration code that Flowguard executes and blocks |
| Native Customer-Service Model Egress | OpenAI API | An existing agent and native tool are protected without adding an agent or tool |
| Customer-Service Export Tool | OpenAI API | Declarative source and sink rules block customer data before an export callback |

## Python MVP PoC

```sh
bash runtimes/python-taint/scripts/run_python_mvp_poc.sh
```

This is the fastest general runtime demo. It executes three generated Python
programs through `FlowguardRuntime.run_python`:

1. A transformed secret reaches HTTP and is blocked as `SecretToNetwork`.
2. Constant telemetry remains allowed after an unrelated secret read.
3. A `json.dumps` precision loss is blocked in strict mode as
   `TaintPrecisionLostToNetwork`.

Implementation: `python_mvp_poc.py`.

## Model Request Guard

```sh
bash runtimes/python-taint/scripts/run_model_request_guard_demo.sh
```

This deterministic OpenAI Agents SDK demo uses a fake model and no API key.
The first public model request asks for a secret-reading tool. Flowguard labels
the tool result and blocks the second request before the fake provider receives
the secret. It demonstrates that the model call itself is an egress boundary.

Implementation: `model_request_guard_demo.py`.

## LangChain And LangGraph

```sh
bash runtimes/python-taint/scripts/run_langchain_leak_demo.sh
```

This offline demo converts protected tools to LangChain `StructuredTool`
objects, which are also accepted by LangGraph tool nodes. A transformed secret
is blocked before the fake HTTP transport. Without `langchain-core`, the same
scenario runs directly and reports that adapter registration was skipped.

Implementation: `langchain_secret_leak.py`.

## Live OpenAI Agent

```sh
export OPENAI_API_KEY="..."
bash runtimes/python-taint/scripts/run_openai_live_agent_leak_demo.sh
```

A real OpenAI-backed agent receives an `execute_python` tool and generates the
Python attack itself. The generated program reads a fake secret, transforms it,
and attempts HTTP exfiltration. Flowguard blocks before the fake destination is
called. This demonstrates the generated-code instrumentation path rather than
only a scripted tool sequence.

Implementation: `openai_live_agent_leak_demo.py`.

## Native Customer-Service Model Egress

```sh
git submodule update --init --recursive
export OPENAI_API_KEY="..."
bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_model_egress_demo.sh
```

This demo protects the existing `openai/openai-cs-agents-demo` graph without
adding an agent or tool. It runs three isolated cases:

1. `baseline-sensitive`: native `get_trip_details` output is labeled
   `CustomerData` and allowed to reach the external model.
2. `protected-sensitive`: the same second model request is blocked as
   `CustomerDataToExternalModel` before the provider call.
3. `protected-public`: public FAQ data remains allowed with zero violations.

Implementation: `../integrations/openai-cs-agents-demo/run_model_egress_demo.py`.

Run the same protected graph interactively:

```sh
bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_model_egress_demo.sh \
  --interactive
```

Try `What is the baggage allowance?` to see an allowed public request. Then
try `Summarize my Paris to New York to Austin trip.` to see
`CustomerDataToExternalModel` blocked before the second provider call. Each
prompt uses fresh airline and provenance state. Type `quit` to exit.

## Customer-Service Export Tool

```sh
git submodule update --init --recursive
export OPENAI_API_KEY="..."
bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_leak_demo.sh
```

This alternate customer-service demo adds one controlled export tool, but no
agent. Declarative source rules classify native customer-data tool outputs.
The model is allowed to process that data, while a matching sink rule blocks
`upload_customer_record` before its callback executes. Baseline reaches the
local receiver; protected mode reports `CustomerDataToNetwork` with zero
receiver calls.

Set `FLOWGUARD_OPENAI_CS_SCENARIO=benign` to access customer data without
calling the export tool. Both modes must remain allowed.

Implementation: `../integrations/openai-cs-agents-demo/run_leak_demo.py`.

## Focused Developer Examples

These files expose individual APIs without the full one-command packaging:

- `explicit_secret_leak.py`: explicit `runtime.open` and `runtime.http` use.
- `generated_code_secret_leak.py`: minimal blocked and allowed generated-code
  cases with JSON/JSONL export.
- `openai_agents_secret_leak.py`: OpenAI tool-schema adaptation with a
  deterministic direct tool invocation.

Run one locally with the runtime on `PYTHONPATH`, for example:

```sh
PYTHONPATH=runtimes/python-taint/src \
  python3 runtimes/python-taint/demos/explicit_secret_leak.py
```

The Python taint eval suite is separate from these demonstrations. Run it with
`bash runtimes/python-taint/scripts/run_python_taint_eval.sh`.
