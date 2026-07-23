#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$RUNTIME_ROOT/../.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${FLOWGUARD_AGENT_OUT_DIR:-logs}"
NAME="${FLOWGUARD_AGENT_NAME:-openai-live-agent-demo}"
MODEL="${FLOWGUARD_AGENT_MODEL:-gpt-5-nano}"
IMAGE="${FLOWGUARD_AGENT_IMAGE:-flowguard-python-taint-demo}"

run_local() {
  export PYTHONPATH="$RUNTIME_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
  python3 "$RUNTIME_ROOT/demos/openai_live_agent_leak_demo.py" \
    --out-dir "$OUT_DIR" \
    --name "$NAME" \
    --model "$MODEL"
}

if [[ "${FLOWGUARD_AGENT_LOCAL:-0}" == "1" ]]; then
  run_local
  exit 0
fi

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "OPENAI_API_KEY is required for the live OpenAI Agents SDK demo" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required; set FLOWGUARD_AGENT_LOCAL=1 to run without Docker" >&2
  exit 2
fi

if [[ "$OUT_DIR" = /* ]]; then
  OUT_DIR_HOST="$OUT_DIR"
else
  OUT_DIR_HOST="$REPO_ROOT/$OUT_DIR"
fi
mkdir -p "$OUT_DIR_HOST"

if [[ "${FLOWGUARD_AGENT_SKIP_DOCKER_BUILD:-0}" != "1" ]]; then
  docker build \
    -f "$RUNTIME_ROOT/docker/Dockerfile" \
    -t "$IMAGE" \
    "$RUNTIME_ROOT"
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

if [[ -n "${FLOWGUARD_AGENT_DOCKER_EXTRA_ARGS:-}" ]]; then
  read -r -a extra_args <<<"$FLOWGUARD_AGENT_DOCKER_EXTRA_ARGS"
  docker_args+=("${extra_args[@]}")
fi

docker run "${docker_args[@]}" "$IMAGE" \
  python3 /runtime/demos/openai_live_agent_leak_demo.py \
  --out-dir /logs \
  --name "$NAME" \
  --model "$MODEL"
