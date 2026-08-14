#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$RUNTIME_ROOT/../.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${FLOWGUARD_MODEL_GUARD_OUT_DIR:-logs}"
NAME="${FLOWGUARD_MODEL_GUARD_NAME:-model-request-guard-demo}"
IMAGE="${FLOWGUARD_MODEL_GUARD_IMAGE:-flowguard-python-taint-demo}"

run_local() {
  export PYTHONPATH="$RUNTIME_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
  python3 "$RUNTIME_ROOT/demos/model_request_guard_demo.py" \
    --out-dir "$OUT_DIR" \
    --name "$NAME"
}

if [[ "${FLOWGUARD_MODEL_GUARD_LOCAL:-0}" == "1" ]]; then
  run_local
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required; set FLOWGUARD_MODEL_GUARD_LOCAL=1 to run locally" >&2
  exit 2
fi

if [[ "$OUT_DIR" = /* ]]; then
  OUT_DIR_HOST="$OUT_DIR"
else
  OUT_DIR_HOST="$REPO_ROOT/$OUT_DIR"
fi
mkdir -p "$OUT_DIR_HOST"

if [[ "${FLOWGUARD_MODEL_GUARD_SKIP_DOCKER_BUILD:-0}" != "1" ]]; then
  docker build \
    -f "$RUNTIME_ROOT/docker/Dockerfile" \
    -t "$IMAGE" \
    "$RUNTIME_ROOT"
fi

docker run \
  --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1 \
  -e HOME=/tmp \
  -e PYTHONPATH=/runtime/src \
  -v "$RUNTIME_ROOT:/runtime:ro" \
  -v "$OUT_DIR_HOST:/logs" \
  -w /runtime \
  "$IMAGE" \
  python3 /runtime/demos/model_request_guard_demo.py \
  --out-dir /logs \
  --name "$NAME"
