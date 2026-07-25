from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib import request

from flowguard import FlowguardBlocked, FlowguardRuntime
from flowguard.ast_policy import AstPolicyViolation

from .cases import EvalCase, all_case_ids, selected_cases

EVAL_SCHEMA_VERSION = "flowguard.python_taint_eval.v1"
SECRET_CONTENT = "PRIVATE KEY\n"
DEFAULT_URL = "https://evil.example/upload"


@dataclass(frozen=True, slots=True)
class EvalArtifacts:
    report_path: Path
    events_path: Path
    summary_path: Path


@dataclass(frozen=True, slots=True)
class NetworkCall:
    target: str
    has_data: bool
    body_length: int | None


@dataclass(frozen=True, slots=True)
class EvalCaseResult:
    id: str
    title: str
    description: str
    precision_mode: str
    expected_outcome: str
    observed_outcome: str
    passed: bool
    expected_policy: str | None
    observed_policy: str | None
    expected_precision_losses: int
    observed_precision_losses: int
    expected_network_calls: int
    observed_network_calls: int
    violation_policies: list[str]
    precision_loss_operations: list[str]
    generated_code_hash: str | None
    error_type: str | None
    error_message: str | None
    duration_ms: float
    report_summary: dict[str, Any]
    tags: list[str]


@dataclass(frozen=True, slots=True)
class EvalRunResult:
    artifacts: EvalArtifacts
    case_results: list[EvalCaseResult]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.case_results)


def run_eval(
    *,
    out_dir: Path,
    name: str,
    case_ids: tuple[str, ...] = (),
    output: TextIO = sys.stdout,
) -> EvalRunResult:
    cases = selected_cases(case_ids)
    out_dir.mkdir(parents=True, exist_ok=True)

    case_results: list[EvalCaseResult] = []
    event_records: list[dict[str, Any]] = []

    _print(output, "Flowguard Python Taint Eval")
    _print(output, f"cases={len(cases)}")

    for case in cases:
        result, events = _run_case(case)
        case_results.append(result)
        event_records.extend(_case_event_records(case, events, len(event_records)))
        status = "PASS" if result.passed else "FAIL"
        policy = result.observed_policy or "-"
        _print(output, f"{status} {case.id}: {result.observed_outcome} policy={policy}")

    artifacts = _write_artifacts(
        out_dir=out_dir,
        name=name,
        case_results=case_results,
        event_records=event_records,
    )

    passed = sum(1 for result in case_results if result.passed)
    failed = len(case_results) - passed
    _print(output, "")
    _print(output, f"summary: passed={passed} failed={failed}")
    _print(output, "artifacts:")
    _print(output, f"  {artifacts.report_path}")
    _print(output, f"  {artifacts.events_path}")
    _print(output, f"  {artifacts.summary_path}")

    if failed:
        failed_ids = ", ".join(result.id for result in case_results if not result.passed)
        raise AssertionError(f"python taint eval failed: {failed_ids}")

    return EvalRunResult(artifacts=artifacts, case_results=case_results)


def _run_case(case: EvalCase) -> tuple[EvalCaseResult, list[dict[str, Any]]]:
    started = time.perf_counter()
    calls: list[NetworkCall] = []
    original_urlopen = request.urlopen
    runtime: FlowguardRuntime | None = None
    observed_outcome = "allowed"
    observed_policy: str | None = None
    error_type: str | None = None
    error_message: str | None = None

    request.urlopen = _fake_urlopen(calls)
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text(SECRET_CONTENT, encoding="utf-8")
            runtime = FlowguardRuntime(
                secret_paths=[secret_path],
                precision_mode=case.precision_mode,
            )
            try:
                runtime.run_python(
                    case.code,
                    inputs={
                        "secret_path": str(secret_path),
                        "url": DEFAULT_URL,
                    },
                )
            except FlowguardBlocked as err:
                observed_outcome = "blocked"
                observed_policy = err.policy
                error_type = type(err).__name__
                error_message = err.explanation
            except AstPolicyViolation as err:
                observed_outcome = "preflight_blocked"
                observed_policy = "AstPolicyViolation"
                error_type = type(err).__name__
                error_message = str(err)
            except Exception as err:  # pragma: no cover - exercised by failed evals.
                observed_outcome = "unexpected_error"
                error_type = type(err).__name__
                error_message = str(err)

            report = runtime.report()
            duration_ms = (time.perf_counter() - started) * 1000
            generated_code_hash = _generated_code_hash(report.events)
            violation_policies = [violation.policy for violation in report.violations]
            precision_loss_operations = [
                loss.operation for loss in report.precision_losses
            ]
            result = EvalCaseResult(
                id=case.id,
                title=case.title,
                description=case.description,
                precision_mode=case.precision_mode,
                expected_outcome=case.expected_outcome,
                observed_outcome=observed_outcome,
                passed=_case_passed(
                    case,
                    observed_outcome=observed_outcome,
                    observed_policy=observed_policy,
                    observed_precision_losses=report.summary.precision_loss_count,
                    observed_network_calls=len(calls),
                ),
                expected_policy=case.expected_policy,
                observed_policy=observed_policy,
                expected_precision_losses=case.expected_precision_losses,
                observed_precision_losses=report.summary.precision_loss_count,
                expected_network_calls=case.expected_network_calls,
                observed_network_calls=len(calls),
                violation_policies=violation_policies,
                precision_loss_operations=precision_loss_operations,
                generated_code_hash=generated_code_hash,
                error_type=error_type,
                error_message=error_message,
                duration_ms=round(duration_ms, 3),
                report_summary=asdict(report.summary),
                tags=list(case.tags),
            )
            return result, report.events
    finally:
        request.urlopen = original_urlopen


def _case_passed(
    case: EvalCase,
    *,
    observed_outcome: str,
    observed_policy: str | None,
    observed_precision_losses: int,
    observed_network_calls: int,
) -> bool:
    if observed_outcome != case.expected_outcome:
        return False
    if observed_policy != case.expected_policy:
        return False
    if observed_precision_losses != case.expected_precision_losses:
        return False
    return observed_network_calls == case.expected_network_calls


def _fake_urlopen(calls: list[NetworkCall]) -> Any:
    def fake(url: Any, data: Any = None, *args: Any, **kwargs: Any) -> bytes:
        del args, kwargs
        request_data = getattr(url, "data", None)
        body = data if data is not None else request_data
        calls.append(
            NetworkCall(
                target=str(getattr(url, "full_url", url)),
                has_data=body is not None,
                body_length=len(body) if hasattr(body, "__len__") else None,
            )
        )
        return b"ok"

    return fake


def _generated_code_hash(events: list[dict[str, Any]]) -> str | None:
    for event in events:
        if event.get("type") == "generated_code_start":
            details = event.get("details")
            if isinstance(details, dict):
                code_hash = details.get("code_hash")
                if code_hash is not None:
                    return str(code_hash)
    return None


def _case_event_records(
    case: EvalCase,
    events: list[dict[str, Any]],
    start_sequence: int,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for offset, event in enumerate(events):
        records.append(
            {
                "suite_sequence": start_sequence + offset,
                "case_id": case.id,
                "case_sequence": event.get("sequence"),
                "event": event,
            }
        )
    return records


def _write_artifacts(
    *,
    out_dir: Path,
    name: str,
    case_results: list[EvalCaseResult],
    event_records: list[dict[str, Any]],
) -> EvalArtifacts:
    report_path = out_dir / f"{name}.report.json"
    events_path = out_dir / f"{name}.events.jsonl"
    summary_path = out_dir / f"{name}.summary.md"

    report_path.write_text(
        f"{json.dumps(_eval_report(case_results), indent=2, sort_keys=True)}\n",
        encoding="utf-8",
    )
    with events_path.open("w", encoding="utf-8") as handle:
        for record in event_records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")
    summary_path.write_text(_summary_markdown(case_results), encoding="utf-8")

    return EvalArtifacts(
        report_path=report_path,
        events_path=events_path,
        summary_path=summary_path,
    )


def _eval_report(case_results: list[EvalCaseResult]) -> dict[str, Any]:
    passed = sum(1 for result in case_results if result.passed)
    failed = len(case_results) - passed
    return {
        "schema_version": EVAL_SCHEMA_VERSION,
        "summary": {
            "case_count": len(case_results),
            "passed": passed,
            "failed": failed,
        },
        "cases": [asdict(result) for result in case_results],
    }


def _summary_markdown(case_results: list[EvalCaseResult]) -> str:
    lines = [
        "# Flowguard Python Taint Eval",
        "",
        "| Case | Result | Outcome | Policy | Precision Losses | Network Calls |",
        "| --- | --- | --- | --- | ---: | ---: |",
    ]
    for result in case_results:
        status = "PASS" if result.passed else "FAIL"
        policy = result.observed_policy or "-"
        lines.append(
            "| "
            f"{result.id} | {status} | {result.observed_outcome} | {policy} | "
            f"{result.observed_precision_losses} | {result.observed_network_calls} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.list:
        for case_id in all_case_ids():
            print(case_id)
        return 0

    try:
        run_eval(
            out_dir=args.out_dir,
            name=args.name,
            case_ids=tuple(args.case),
            output=sys.stdout,
        )
    except (AssertionError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run deterministic Flowguard Python taint eval cases.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("logs"),
        help="Directory where eval artifacts are written.",
    )
    parser.add_argument(
        "--name",
        default="python-taint-eval",
        help="Base artifact name.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run one case id. Can be passed multiple times.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available case ids and exit.",
    )
    return parser.parse_args(argv)


def _print(output: TextIO, text: str) -> None:
    print(text, file=output)


if __name__ == "__main__":
    raise SystemExit(main())

