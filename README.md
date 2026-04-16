# Syscall Provenance Engine for AI Agent Security

## Overview

This project implements a **runtime provenance tracking system** that observes execution events and reconstructs **dataflow at the syscall boundary**.

The goal is to detect and explain unsafe behavior in AI agents and automated systems.

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

## Architecture

events → state → graph → labels → policies → explanationsA

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
