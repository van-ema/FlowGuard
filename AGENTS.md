# AGENTS.md

## Implementation Contract

The following rules are mandatory:

1. Every provenance edge MUST correspond to an observed event.
2. File descriptors MUST be resolved through the FD table — never guessed.
3. The provenance graph MUST be append-only.
4. Label propagation MUST follow defined rules exactly (no implicit propagation).
5. Every policy violation MUST include a reconstructable explanation path.
6. Process identity MUST include PID + start time (PID alone is invalid).
7. Do NOT silently ignore inconsistent state — surface it explicitly.

When in doubt:
→ prefer correctness over performance.

---

## Project Goal

Build a **syscall-level provenance engine** for AI agent security.

The system:
- observes execution events
- builds a dynamic provenance graph
- propagates coarse-grained labels
- detects unsafe dataflows
- explains violations

---

## Core Model

### Nodes
- Process
- File
- Pipe
- Socket
- Endpoint

### Edges
- READ (object → process)
- WRITE (process → object)
- RECV (endpoint → process)
- SEND (process → endpoint)
- FORK (process → process)
- EXEC (process → process)
- CONNECT (process → endpoint)

### Labels
- PROMPT
- EXTERNAL
- SECRET
- TRUSTED_LOCAL
- APPROVED

---

## Architecture Constraints

Keep strict separation:

- event ingestion
- runtime state (process + FD table)
- provenance graph
- label propagation
- policy engine
- explanation engine

Do NOT merge these responsibilities.

---

## Label Propagation Rules

Implement exactly:

- READ:     labels(P) |= labels(O)
- WRITE:    labels(O) |= labels(P)
- FORK:     labels(child) |= labels(parent)
- EXEC:     labels(child) |= labels(parent)
- RECV:     labels(P) |= {EXTERNAL}

Seed labels:
- secret paths → SECRET
- agent-launched processes → PROMPT
- approved actions → APPROVED

Overtainting is acceptable. Missing flows are not.

---

## Policy Rules (MVP)

### Rule 1: External → Exec
Block or alert when EXTERNAL reaches execution.

### Rule 2: Secret → Network
Block when SECRET reaches SEND.

### Rule 3: Prompt → Shell (no approval)
Require approval if PROMPT executes interpreter without APPROVED.

### Rule 4: External → Executable write
Alert when EXTERNAL writes into executable locations.

Policies must be:
- explicit
- deterministic
- explainable

---

## Provenance Graph Rules

- Graph is append-only
- Every node must exist before edges reference it
- Every edge must include timestamp
- Store minimal metadata for explanations

---

## FD Table Rules

- FD table is authoritative
- No FD → object inference without explicit mapping
- Handle:
  - open
  - pipe
  - dup
  - close

Incorrect FD handling = incorrect provenance

---

## Explanation Requirement

Every alert MUST produce:

- the violated policy
- the sink event
- a backward path to the source

Example:

SECRET → NETWORK violation

file:/home/user/.ssh/id_rsa –READ–> proc:201
proc:201 –WRITE–> pipe:2
pipe:2 –READ–> proc:202
proc:202 –SEND–> ep:evil.com

---

## Development Strategy

### Phase 1 (MANDATORY)
- synthetic events only
- deterministic scenarios
- no kernel integration

### Phase 2
- stabilize graph + labels + policies

### Phase 3
- integrate real event source (eBPF / trace)

---

## How to Implement Features

For every change:

1. Add or update a scenario test
2. Implement minimal logic
3. Verify:
   - graph edges
   - label propagation
   - policy behavior
   - explanation output
4. Refactor only if it improves clarity

Never introduce large changes without tests.

---

## Coding Rules

- Prefer explicit over clever
- Avoid unnecessary abstractions
- Keep functions small
- Use strong domain types
- No hidden state transitions

---

## Failure Handling

Do NOT silently ignore:

- missing FD
- unknown process
- inconsistent state

Instead:
- log structured warning
- keep system running if possible

---

## Non-Goals

Do NOT implement:

- byte-level taint tracking
- full IFC correctness
- browser internals
- distributed tracing
- complex policy DSL

---

## First Milestone

A working scenario for:

`curl | bash`

With:
- correct graph
- correct label propagation
- policy violation
- full explanation

---

## Guiding Principle

This system must always answer:

👉 **"Why did this happen?"**

Clarity of explanation > completeness > performance
