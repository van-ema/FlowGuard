#!/usr/bin/env bash
set -euo pipefail

CRATE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$CRATE_ROOT/../.." && pwd)"
cd "$REPO_ROOT"

case "$(uname -m)" in
  arm64|aarch64)
    DEFAULT_PLATFORM="linux/arm64"
    ;;
  *)
    DEFAULT_PLATFORM="linux/amd64"
    ;;
esac

IMAGE="${FLOWGUARD_PROTECT_IMAGE:-}"
PLATFORM="${FLOWGUARD_DOCKER_PLATFORM:-$DEFAULT_PLATFORM}"
OUT_DIR="${FLOWGUARD_POC_OUT_DIR:-logs}"
NAME="${FLOWGUARD_POC_NAME:-false-positive-secret-unrelated-send}"
REQUESTED_PORT="${FLOWGUARD_POC_PORT:-0}"

REPORT="$OUT_DIR/$NAME.report.json"
STDERR_LOG="$OUT_DIR/$NAME.stderr.log"
SINK_LOG="$OUT_DIR/$NAME.sink.log"
BODY_FILE="$OUT_DIR/$NAME.sink.body"
PORT_FILE="$OUT_DIR/$NAME.port"

mkdir -p "$OUT_DIR"
rm -f "$REPORT" "$STDERR_LOG" "$SINK_LOG" "$BODY_FILE" "$PORT_FILE"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for the false-positive POC" >&2
  exit 2
fi

if [[ -z "$IMAGE" ]]; then
  if docker image inspect flowguard-observer:latest >/dev/null 2>&1; then
    IMAGE="flowguard-observer"
  else
    IMAGE="rust:1-bookworm"
  fi
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the false-positive POC" >&2
  exit 2
fi

python3 -u - "$REQUESTED_PORT" "$PORT_FILE" "$BODY_FILE" >"$SINK_LOG" 2>&1 <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        Path(sys.argv[3]).write_bytes(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


server = HTTPServer(("0.0.0.0", int(sys.argv[1])), Handler)
Path(sys.argv[2]).write_text(str(server.server_port), encoding="utf-8")
server.serve_forever()
PY
SINK_PID=$!

cleanup() {
  kill "$SINK_PID" >/dev/null 2>&1 || true
  wait "$SINK_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  if [[ -s "$PORT_FILE" ]]; then
    break
  fi
  sleep 0.05
done

if [[ ! -s "$PORT_FILE" ]]; then
  echo "POST sink did not start" >&2
  cat "$SINK_LOG" >&2 || true
  exit 1
fi

PORT="$(cat "$PORT_FILE")"

docker_args=(
  --rm
  --platform
  "$PLATFORM"
  --cap-add=SYS_PTRACE
  --security-opt
  seccomp=unconfined
  -v "$REPO_ROOT:/work"
  -v "$CRATE_ROOT/fixtures/home:/home/user:ro"
  -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  -w /work
)

if [[ "$(uname -s)" == "Linux" ]]; then
  docker_args+=(--add-host=host.docker.internal:host-gateway)
fi

if [[ -n "${FLOWGUARD_DOCKER_EXTRA_ARGS:-}" ]]; then
  read -r -a extra_args <<<"$FLOWGUARD_DOCKER_EXTRA_ARGS"
  docker_args+=("${extra_args[@]}")
fi

set +e
docker run "${docker_args[@]}" "$IMAGE" \
  cargo run --manifest-path crates/system-provenance/Cargo.toml -- protect --json \
    -- sh -c "SECRET_PATH=/home/user/.ssh/id_rsa LEAK_URL=http://host.docker.internal:$PORT/telemetry crates/system-provenance/fixtures/agents/false_positive_secret_then_unrelated_send.sh" \
  >"$REPORT" \
  2>"$STDERR_LOG"
status=$?
set -e

if [[ "$status" -ne 1 ]]; then
  echo "expected Flowguard protect to block this coarse-taint false positive with exit code 1, got $status" >&2
  echo "--- cargo/docker stderr ---" >&2
  cat "$STDERR_LOG" >&2 || true
  exit 1
fi

python3 "$CRATE_ROOT/scripts/dump_observe_report.py" "$REPORT" --out-dir "$OUT_DIR" --name "$NAME"

python3 - "$REPORT" "$BODY_FILE" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
body_path = Path(sys.argv[2])
body = body_path.read_bytes() if body_path.exists() else b""

def fail(message: str) -> None:
    raise SystemExit(message)

if body:
    fail(f"POST sink received {len(body)} bytes; protect should block before unrelated telemetry egress")

if report.get("decision", {}).get("kind") != "Block":
    fail("decision was not Block")

violations = report.get("violations") or []
if not any(v.get("policy") == "SecretToNetwork" for v in violations):
    fail("missing SecretToNetwork violation")

explanations = [
    explanation
    for explanation in report.get("explanations", [])
    if explanation.get("policy") == "SecretToNetwork"
]
if not explanations:
    fail("missing SecretToNetwork explanation")

path = explanations[0].get("path") or []
if not any(step.get("from_display", "").startswith("file:/home/user/.ssh/id_rsa") for step in path):
    fail("explanation path does not include the secret file")

if not path[-1].get("to_display", "").startswith("endpoint:"):
    fail("explanation does not end at a network endpoint")

print("validated expected coarse-taint false positive and empty POST body")
PY

echo "false-positive POC passed"
echo "report: $REPORT"
echo "violation log: $OUT_DIR/$NAME.violation.log"
echo "graph dot: $OUT_DIR/$NAME.graph.dot"
echo "graph mermaid: $OUT_DIR/$NAME.graph.mmd"
