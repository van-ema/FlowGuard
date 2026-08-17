# OpenAI Customer Service Agent Hardening

This overlay protects the existing agents from the
`openai/openai-cs-agents-demo` submodule without changing upstream code. It:

- traverses and protects the cyclic airline handoff graph;
- explicitly protects the two guardrail agents hidden in callbacks;
- runs existing SDK tools inside Flowguard's file, network, and subprocess guards;
- permits the approved model to process the controlled customer record while
  preserving its provenance;
- blocks the model-derived record before the untrusted transport is called.

Run the live demo in a restricted Docker container:

```sh
git submodule update --init --recursive
export OPENAI_API_KEY="..."
bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_leak_demo.sh
```

Expected result:

```text
Flowguard OpenAI Customer Service Hardening Demo
result: BLOCKED SecretToNetwork
network_calls=0
```

Reports are written to:

- `logs/openai-cs-flowguard-demo.report.json`
- `logs/openai-cs-flowguard-demo.events.jsonl`

The fixture contains fake data only. The report records its source and
transformation path, but not its contents.

The full upstream ChatKit backend can use the protected server overlay:

```sh
export PYTHONPATH="$PWD/runtimes/python-taint/src"
cd runtimes/python-taint/integrations/openai-cs-agents-demo
uvicorn app:app --host 127.0.0.1 --port 8000
```

`FlowguardAirlineServer` creates a fresh sidecar provenance scope around each
complete streamed response. The current content-safe report is available at
`http://127.0.0.1:8000/flowguard/report`.

Local mode uses the upstream backend dependencies installed in the active
environment:

```sh
python3 -m pip install -r \
  runtimes/python-taint/integrations/openai-cs-agents-demo/upstream/python-backend/requirements.txt
FLOWGUARD_OPENAI_CS_LOCAL=1 \
  bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_leak_demo.sh
```
