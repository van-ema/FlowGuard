# OpenAI Customer Service Agent Hardening

This overlay protects the existing agents from the
`openai/openai-cs-agents-demo` submodule without changing upstream code. It:

- traverses and protects the cyclic airline handoff graph;
- explicitly protects the two guardrail agents hidden in callbacks;
- labels plain outputs from native customer-data tools such as
  `get_trip_details` without changing upstream code;
- runs existing SDK tools inside Flowguard's file, network, and subprocess guards;
- blocks native customer data before the next external model request;
- permits the approved model to process customer trip data while
  preserving its provenance;
- blocks the model-derived record before the controlled export callback runs.

Run the live demo in a restricted Docker container:

```sh
git submodule update --init --recursive
export OPENAI_API_KEY="..."
bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_model_egress_demo.sh
```

Expected result:

```text
Flowguard Native Model Egress Demo
case: baseline-sensitive
result: DATA_REACHED_MODEL
Flowguard Native Model Egress Demo
case: protected-sensitive
result: BLOCKED CustomerDataToExternalModel
Flowguard Native Model Egress Demo
case: protected-public
result: ALLOWED
```

This path adds no agent or tool. Baseline records that labeled customer data
reached OpenAI, protected-sensitive blocks before the second provider request,
and protected-public verifies that public FAQ data remains allowed.

Run the protected graph interactively:

```sh
bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_model_egress_demo.sh \
  --interactive
```

Public FAQ prompts are allowed. Prompts that retrieve native trip details are
blocked before those details enter the next external model request. Each input
uses fresh state; type `quit` to exit. Interactive reports are written to
`logs/openai-cs-model-egress-demo.interactive.{report.json,events.jsonl}`.

The controlled export-tool scenario remains available through
`run_leak_demo.sh`. Its `benign` variant accesses customer data through an
approved model but does not invoke the export sink.

Reports are written to:

- `logs/openai-cs-flowguard-demo.report.json`
- `logs/openai-cs-flowguard-demo.events.jsonl`
- `logs/openai-cs-flowguard-demo.baseline.summary.json`
- `logs/openai-cs-flowguard-demo.protected.summary.json`
- `logs/openai-cs-flowguard-demo.benign.baseline.summary.json`
- `logs/openai-cs-flowguard-demo.benign.protected.summary.json`
- `logs/openai-cs-flowguard-demo.benign.report.json`
- `logs/openai-cs-flowguard-demo.benign.events.jsonl`
- `logs/openai-cs-model-egress-demo.baseline-sensitive.{summary,report}.json`
- `logs/openai-cs-model-egress-demo.baseline-sensitive.events.jsonl`
- `logs/openai-cs-model-egress-demo.protected-sensitive.{summary,report}.json`
- `logs/openai-cs-model-egress-demo.protected-sensitive.events.jsonl`
- `logs/openai-cs-model-egress-demo.protected-public.{summary,report}.json`
- `logs/openai-cs-model-egress-demo.protected-public.events.jsonl`

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
  bash runtimes/python-taint/integrations/openai-cs-agents-demo/run_model_egress_demo.sh
```
