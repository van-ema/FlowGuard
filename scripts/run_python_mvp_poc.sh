#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="$ROOT_DIR/python/src${PYTHONPATH:+:$PYTHONPATH}"

OUT_DIR="${FLOWGUARD_POC_OUT_DIR:-logs}"
NAME="${FLOWGUARD_POC_NAME:-python-mvp-poc}"

python3 examples/python_mvp_poc.py \
  --out-dir "$OUT_DIR" \
  --name "$NAME"
