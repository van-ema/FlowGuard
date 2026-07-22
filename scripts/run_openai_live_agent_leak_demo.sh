#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT_DIR/python/src${PYTHONPATH:+:$PYTHONPATH}"

OUT_DIR="${FLOWGUARD_AGENT_OUT_DIR:-logs}"
NAME="${FLOWGUARD_AGENT_NAME:-openai-live-agent-demo}"
MODEL="${FLOWGUARD_AGENT_MODEL:-gpt-5-nano}"

python3 "$ROOT_DIR/examples/openai_live_agent_leak_demo.py" \
  --out-dir "$OUT_DIR" \
  --name "$NAME" \
  --model "$MODEL"
