#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$RUNTIME_ROOT/../.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${FLOWGUARD_EVAL_OUT_DIR:-logs}"
NAME="${FLOWGUARD_EVAL_NAME:-python-taint-eval}"

export PYTHONPATH="$RUNTIME_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
python3 "$RUNTIME_ROOT/evals/run_eval.py" \
  --out-dir "$OUT_DIR" \
  --name "$NAME" \
  "$@"

