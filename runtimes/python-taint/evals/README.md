# Flowguard Python Taint Eval

This package runs deterministic offline security-correctness cases for the
Python dynamic taint runtime.

Run all cases:

```sh
bash runtimes/python-taint/scripts/run_python_taint_eval.sh
```

List available cases:

```sh
bash runtimes/python-taint/scripts/run_python_taint_eval.sh --list
```

Run one case:

```sh
bash runtimes/python-taint/scripts/run_python_taint_eval.sh \
  --case json_precision_loss_warn
```

Artifacts:

- `logs/python-taint-eval.report.json`
- `logs/python-taint-eval.events.jsonl`
- `logs/python-taint-eval.summary.md`

The eval is not a performance benchmark. It checks whether supported source,
transform, sink, precision-loss, and unsupported-path cases produce the expected
allow/block result without using the network.

