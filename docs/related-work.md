# Related Work

Flowguard combines ideas from whole-system provenance, runtime security detection, Linux sandboxing, and agent safety. The goal is not to clone any one project. The goal is to build an agent-focused provenance and enforcement engine with deterministic policy decisions and reconstructable explanations.

## CamFlow

CamFlow is the closest conceptual match. It captures whole-system provenance through Linux hooks such as LSM and NetFilter and can represent process, file, and network causality as a provenance graph.

What Flowguard should reuse:

- graph discipline: explicit provenance nodes and edges
- object-state versioning ideas if Flowguard explanations become ambiguous
- capture-policy ideas such as track, propagate, and opaque
- output/import ideas such as W3C PROV or SPADE-style graph exchange
- deployment lesson: OS-level provenance is practical but kernel integration affects portability

What Flowguard should not reuse directly:

- do not fork CamFlow as the core engine
- do not require a CamFlow-patched kernel for the MVP
- do not replace Flowguard policies with CamQuery-style graph queries

Reason:

CamFlow is provenance capture and audit infrastructure. Flowguard is agent-focused prevention. Flowguard needs labels such as `PROMPT`, `SECRET`, `EXTERNAL`, and `APPROVED`, plus blocking decisions and short human explanations.

Possible future integration:

```text
CamFlow output -> Flowguard normalizer -> graph -> labels -> policy -> explanation
```

## Falco

Falco is mature syscall-based runtime detection. It is useful for event taxonomy, suspicious behavior examples, rule authoring style, container metadata, and alert outputs.

What Flowguard should reuse:

- syscall event vocabulary
- detection examples for shell execution, sensitive file access, container escape behavior, and unexpected network activity
- practical rule categories for runtime security

What Flowguard should not reuse directly:

- do not fork Falco
- do not make Falco rules the core policy model

Reason:

Falco rules are mostly event predicates. Flowguard needs stateful provenance: FD resolution, append-only graph edges, label propagation, and explanation paths.

Possible future integration:

```text
Falco events -> Flowguard normalizer -> provenance/policy engine
```

## Tetragon

Tetragon is relevant for eBPF-based runtime visibility and enforcement. It can observe kernel events and apply enforcement actions such as signal delivery or return-value override.

What Flowguard should reuse:

- eBPF event-source design ideas
- enforcement lessons, especially the difference between killing a process after an event and blocking a syscall before it completes
- Kubernetes-aware deployment ideas

Flowguard-specific need:

Tetragon can supply events or enforcement hooks, but Flowguard still owns provenance labels, policy decisions, and explanation paths.

## KubeArmor

KubeArmor is relevant for LSM-backed workload enforcement over process, file, and network behavior.

What Flowguard should reuse:

- policy categories for process/file/network restrictions
- LSM-backed enforcement model
- Kubernetes workload policy deployment ideas

Flowguard-specific need:

KubeArmor-style policy can block sandbox escape primitives, while Flowguard explains why a dataflow-sensitive action was unsafe.

## Tracee

Tracee is relevant as an eBPF event collector and runtime security detector.

What Flowguard should reuse:

- event collection patterns
- suspicious syscall behavior catalog
- container-aware event enrichment ideas

Possible future integration:

```text
Tracee events -> Flowguard normalizer -> provenance/policy engine
```

## Linux Sandboxing Primitives

Flowguard should use existing Linux enforcement mechanisms instead of relying only on post-event detection.

Relevant mechanisms:

- seccomp: reduce syscall surface and broker selected syscalls with user notification
- Landlock: unprivileged filesystem and network access restrictions
- AppArmor and SELinux: profile-based access control
- BPF-LSM: low-level enforcement hooks where available
- namespaces and cgroups: isolation and resource control, but not sufficient alone

Flowguard role:

These mechanisms enforce static boundaries. Flowguard adds dynamic provenance-aware decisions.

## gVisor and Firecracker

gVisor and Firecracker are stronger sandbox substrates.

What Flowguard should reuse:

- deployment option for high-risk agent execution
- isolation boundary underneath Flowguard

What Flowguard should not do:

- do not treat them as replacements for provenance

Reason:

They isolate workloads, but they do not explain agent dataflow or policy violations.

## SPADE and PASS

SPADE and PASS are provenance-system references.

What Flowguard should reuse:

- graph exchange and storage ideas
- provenance query ideas
- separation between collection, storage, and analysis

Flowguard-specific need:

Flowguard keeps a smaller, security-focused provenance graph with coarse labels and deterministic enforcement.

## Design Decision

Flowguard should remain its own Rust core:

```text
event source -> normalizer -> state -> graph -> labels -> policy -> enforce -> explain
```

External systems can be adapters:

- CamFlow adapter for whole-system provenance logs
- Falco or Tracee adapter for syscall detections/events
- Tetragon or BPF-LSM integration for live enforcement
- KubeArmor/AppArmor/seccomp/Landlock integration for static confinement

This keeps the MVP simple while leaving a clear path to live kernel-backed enforcement.
