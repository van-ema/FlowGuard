#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$RUNTIME_ROOT/../.." && pwd)"
cd "$REPO_ROOT"

export PYTHONPATH="$RUNTIME_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

OUT_DIR="${FLOWGUARD_POC_OUT_DIR:-logs}"
NAME="${FLOWGUARD_POC_NAME:-python-mvp-poc}"

python3 "$RUNTIME_ROOT/demos/python_mvp_poc.py" \
  --out-dir "$OUT_DIR" \
  --name "$NAME"
