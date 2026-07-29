#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$RUNTIME_ROOT/../.." && pwd)"
cd "$REPO_ROOT"

export PYTHONPATH="$RUNTIME_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

OUT_DIR="${FLOWGUARD_LANGCHAIN_OUT_DIR:-logs}"
NAME="${FLOWGUARD_LANGCHAIN_NAME:-langchain-secret-leak}"

python3 "$RUNTIME_ROOT/demos/langchain_secret_leak.py" \
  --out-dir "$OUT_DIR" \
  --name "$NAME"
