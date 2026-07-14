# Design: Syscall-Level Provenance for Agent Security

This document describes the low-level syscall provenance layer. For the updated product goal and trusted-runtime architecture, see [Flowguard Vision and Design](flowguard-vision-design.md).

## Problem

AI agents execute actions that can:
- read sensitive data
- execute commands
- interact with external systems

We need to detect unsafe behavior such as:
- execution of untrusted content
- data exfiltration
- unsafe autonomous actions

---

## Approach

We track **dynamic provenance at the syscall boundary**.

Instead of analyzing code statically, we observe:

- process behavior
- file access
- network activity
- inter-process communication

---

## Core Model

### Graph

A directed graph:

Nodes:
- Process
- File
- Pipe
- Socket
- Endpoint

Edges:
- READ
- WRITE
- RECV
- SEND
- FORK
- EXEC
- CONNECT

---

## Dataflow Semantics

We approximate dataflow using:

- READ: object → process
- WRITE: process → object
- RECV: endpoint → process
- SEND: process → endpoint

This is **coarse-grained provenance**.

---

## Labels

We assign semantic labels:

- PROMPT: derived from LLM output
- EXTERNAL: derived from network
- SECRET: sensitive local data
- TRUSTED_LOCAL: safe local files
- APPROVED: user-approved actions

---

## Propagation

Labels propagate via graph edges:

- read → process taint
- write → object taint
- fork/exec → process taint
- network receive → EXTERNAL

This is a conservative model.

---

## Policies

We detect unsafe flows:

### External → Exec
Untrusted data executed

### Secret → Network
Data exfiltration

### Prompt → Shell
Unsafe agent action

---

## Example: curl | bash

endpoint → curl → pipe → bash → exec
Flow:
EXTERNAL → EXEC

---

## Tradeoffs

### Pros
- language-agnostic
- hard to bypass
- works across tools
- explainable

### Cons
- coarse-grained (overtainting)
- no byte-level precision
- limited semantic insight

---

## Why Not Static Analysis?

Agents are dynamic:
- runtime decisions
- external data
- tool composition

Static analysis is insufficient.

---

## Why Syscalls?

All actions eventually become:
- file access
- process creation
- network activity

Syscalls provide:
- ground truth
- uniform interface

---

## Limitations

- cannot prove exact byte flow
- cannot see in-memory transformations
- limited visibility into high-level intent

---

## Future Work

- integration with eBPF
- better policy language
- hybrid semantic + syscall tracking
- visualization tools
- performance optimization

---

## Research Angle

This system explores:

> Dynamic information flow tracking for AI agents using syscall-level provenance.

Key novelty:
- combining OS-level provenance with agent-level semantics

---

## Summary

We build a system that:

- observes execution
- reconstructs dataflow
- detects unsafe behavior
- explains causality

The focus is not perfect precision, but **practical, enforceable security insight**.
