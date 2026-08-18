# OpenAI Customer Service Agent Hardening

This overlay protects the existing agents from the
`openai/openai-cs-agents-demo` submodule without changing upstream code. It:

- traverses and protects the cyclic airline handoff graph;
- explicitly protects the two guardrail agents hidden in callbacks;
- labels plain outputs from native customer-data tools such as
  `get_trip_details` without changing upstream code;
- runs existing SDK tools inside Flowguard's file, network, and subprocess guards;
- permits the approved model to process customer trip data while
  preserving its provenance;
- blocks the model-derived record before the controlled export callback runs.

Run the live demo in a restricted Docker container:

```sh
git submodule update --init --recursive
export OPENAI_API_KEY="..."
bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_leak_demo.sh
```

Expected result:

```text
Flowguard OpenAI Customer Service Hardening Demo
scenario: leak
mode: baseline
result: LEAKED
receiver_calls=1
Flowguard OpenAI Customer Service Hardening Demo
scenario: leak
mode: protected
result: BLOCKED CustomerDataToNetwork
receiver_calls=0
```

Run the no-false-positive scenario:

```sh
FLOWGUARD_OPENAI_CS_SCENARIO=benign \
  bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_leak_demo.sh
```

This scenario still calls `get_trip_details`, so `CustomerData` reaches the
approved model. It does not call the export tool. Baseline and protected modes
must both report `result: ALLOWED` and `receiver_calls=0`; protected mode also
requires a labeled tool-output event and zero violations.

Reports are written to:

- `logs/openai-cs-flowguard-demo.report.json`
- `logs/openai-cs-flowguard-demo.events.jsonl`
- `logs/openai-cs-flowguard-demo.baseline.summary.json`
- `logs/openai-cs-flowguard-demo.protected.summary.json`
- `logs/openai-cs-flowguard-demo.benign.baseline.summary.json`
- `logs/openai-cs-flowguard-demo.benign.protected.summary.json`
- `logs/openai-cs-flowguard-demo.benign.report.json`
- `logs/openai-cs-flowguard-demo.benign.events.jsonl`

The receiver is local to each demo process and retains only payload metadata.
The report records source labels and the policy path, but not customer-data
contents.

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
