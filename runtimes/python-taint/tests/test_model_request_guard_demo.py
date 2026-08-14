from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))

from demos.model_request_guard_demo import DEMO_SECRET, run_demo

try:
    import agents
except ImportError:
    agents = None


@unittest.skipUnless(agents is not None, "OpenAI Agents SDK is not installed")
class ModelRequestGuardDemoTests(unittest.IsolatedAsyncioTestCase):
    async def test_demo_blocks_second_model_call_and_writes_safe_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = io.StringIO()

            artifacts = await run_demo(
                out_dir=Path(tmpdir),
                name="test-model-guard",
                output=output,
            )

            report_text = artifacts.report_path.read_text(encoding="utf-8")
            report = json.loads(report_text)

            self.assertEqual(artifacts.blocked_policy, "SecretToModel")
            self.assertEqual(artifacts.provider_call_count, 1)
            self.assertEqual(report["summary"]["violation_count"], 1)
            self.assertEqual(report["summary"]["model_request_count"], 2)
            self.assertEqual(report["violations"][0]["policy"], "SecretToModel")
            self.assertIn("sensitive_provider_calls=0", output.getvalue())
            self.assertNotIn(DEMO_SECRET, report_text)


if __name__ == "__main__":
    unittest.main()
