from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from examples.python_mvp_poc import run_poc


class PythonMvpPocTests(unittest.TestCase):
    def test_poc_writes_expected_report_and_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            output = io.StringIO()

            artifacts = run_poc(out_dir=out_dir, name="test-poc", output=output)

            report = json.loads(artifacts.report_path.read_text(encoding="utf-8"))
            events = artifacts.events_path.read_text(encoding="utf-8").splitlines()
            policies = {violation["policy"] for violation in report["violations"]}
            stdout = output.getvalue()

            self.assertTrue(artifacts.report_path.exists())
            self.assertTrue(artifacts.events_path.exists())
            self.assertEqual(report["summary"]["violation_count"], 2)
            self.assertEqual(report["summary"]["allowed_send_count"], 1)
            self.assertEqual(report["summary"]["precision_loss_count"], 1)
            self.assertEqual(len(events), report["summary"]["event_count"])
            self.assertIn("SecretToNetwork", policies)
            self.assertIn("TaintPrecisionLostToNetwork", policies)
            self.assertIn("result: BLOCKED SecretToNetwork", stdout)
            self.assertIn("result: ALLOWED", stdout)
            self.assertIn("result: BLOCKED TaintPrecisionLostToNetwork", stdout)
            self.assertNotIn("PRIVATE KEY", artifacts.report_path.read_text())
            self.assertNotIn("PRIVATE KEY", artifacts.events_path.read_text())


if __name__ == "__main__":
    unittest.main()
