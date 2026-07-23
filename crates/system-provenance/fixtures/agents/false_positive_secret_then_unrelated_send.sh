#!/usr/bin/env sh
set -eu

# Human-readable shape for:
#   crates/system-provenance/scenarios/false_positive_secret_then_unrelated_send.yaml
#
# This deliberately demonstrates Flowguard's current coarse process-level taint.
# The process reads a secret, discards it, then sends unrelated constant telemetry.
# A byte-precise engine would allow this request. Flowguard's MVP blocks it
# because the process became SECRET-tainted before network egress.

SECRET_PATH="${SECRET_PATH:-/home/user/.ssh/id_rsa}"
LEAK_URL="${LEAK_URL:-http://127.0.0.1:18000/telemetry}"

secret="$(cat "$SECRET_PATH")"
: "$secret"
unset secret

printf 'ok' | curl -sS -X POST --data-binary @- "$LEAK_URL"
