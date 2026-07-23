#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$RUNTIME_ROOT/../.." && pwd)"
cd "$REPO_ROOT"

export PYTHONPATH="$RUNTIME_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

OUT_DIR="${FLOWGUARD_AGENT_OUT_DIR:-logs}"
NAME="${FLOWGUARD_AGENT_NAME:-openai-live-agent-demo}"
MODEL="${FLOWGUARD_AGENT_MODEL:-gpt-5-nano}"

python3 "$RUNTIME_ROOT/demos/openai_live_agent_leak_demo.py" \
  --out-dir "$OUT_DIR" \
  --name "$NAME" \
  --model "$MODEL"
