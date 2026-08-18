#!/usr/bin/env bash
set -euo pipefail

INTEGRATION_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_ROOT="$(cd "$INTEGRATION_ROOT/../.." && pwd)"
REPO_ROOT="$(cd "$RUNTIME_ROOT/../.." && pwd)"
OUT_DIR="${FLOWGUARD_OPENAI_CS_OUT_DIR:-logs}"
NAME="${FLOWGUARD_OPENAI_CS_MODEL_EGRESS_NAME:-openai-cs-model-egress-demo}"
MODEL="${FLOWGUARD_OPENAI_CS_MODEL:-gpt-5-nano}"
IMAGE="${FLOWGUARD_OPENAI_CS_IMAGE:-flowguard-openai-cs-demo}"
CASES=(baseline-sensitive protected-sensitive protected-public)
INTERACTIVE=0

if [[ "${1:-}" == "--interactive" ]]; then
  INTERACTIVE=1
  shift
fi
if [[ "$#" -ne 0 ]]; then
  echo "usage: $0 [--interactive]" >&2
  exit 2
fi

cd "$REPO_ROOT"

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "OPENAI_API_KEY is required for the live demo" >&2
  exit 2
fi

if [[ ! -f "$INTEGRATION_ROOT/upstream/python-backend/requirements.txt" ]]; then
  echo "initialize submodules with: git submodule update --init --recursive" >&2
  exit 2
fi

if [[ "${FLOWGUARD_OPENAI_CS_LOCAL:-0}" == "1" ]]; then
  export PYTHONPATH="$RUNTIME_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
  if [[ "$INTERACTIVE" == "1" ]]; then
    python3 "$INTEGRATION_ROOT/run_model_egress_demo.py" \
      --interactive \
      --out-dir "$OUT_DIR" \
      --name "$NAME" \
      --model "$MODEL"
    exit 0
  fi
  for case_name in "${CASES[@]}"; do
    python3 "$INTEGRATION_ROOT/run_model_egress_demo.py" \
      --case "$case_name" \
      --out-dir "$OUT_DIR" \
      --name "$NAME" \
      --model "$MODEL"
  done
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required; set FLOWGUARD_OPENAI_CS_LOCAL=1 for local mode" >&2
  exit 2
fi

if [[ "$OUT_DIR" = /* ]]; then
  OUT_DIR_HOST="$OUT_DIR"
else
  OUT_DIR_HOST="$REPO_ROOT/$OUT_DIR"
fi
mkdir -p "$OUT_DIR_HOST"

if [[ "${FLOWGUARD_OPENAI_CS_SKIP_DOCKER_BUILD:-0}" != "1" ]]; then
  docker build \
    -f "$INTEGRATION_ROOT/Dockerfile" \
    -t "$IMAGE" \
    "$INTEGRATION_ROOT"
fi

docker_args=(
  --rm
  --network bridge
  --read-only
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m
  --cap-drop=ALL
  --security-opt no-new-privileges
  --pids-limit 128
  --memory 512m
  --cpus 1
  -e OPENAI_API_KEY
  -e HOME=/tmp
  -e PYTHONPATH=/runtime/src
  -v "$RUNTIME_ROOT:/runtime:ro"
  -v "$OUT_DIR_HOST:/logs"
  -w /runtime
)

if [[ "$INTERACTIVE" == "1" ]]; then
  docker run -it "${docker_args[@]}" "$IMAGE" \
    python3 /runtime/integrations/openai-cs-agents-demo/run_model_egress_demo.py \
      --interactive \
      --out-dir /logs \
      --name "$NAME" \
      --model "$MODEL"
  exit 0
fi

for case_name in "${CASES[@]}"; do
  docker run "${docker_args[@]}" "$IMAGE" \
    python3 /runtime/integrations/openai-cs-agents-demo/run_model_egress_demo.py \
      --case "$case_name" \
      --out-dir /logs \
      --name "$NAME" \
      --model "$MODEL"
done
