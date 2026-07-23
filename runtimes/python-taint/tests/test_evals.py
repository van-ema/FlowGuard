from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))

from evals.cases import all_case_ids
from evals.runner import EVAL_SCHEMA_VERSION, run_eval


class PythonTaintEvalTests(unittest.TestCase):
    def test_eval_runs_all_cases_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            output = io.StringIO()

            result = run_eval(out_dir=out_dir, name="test-eval", output=output)

            report_text = result.artifacts.report_path.read_text(encoding="utf-8")
            events_text = result.artifacts.events_path.read_text(encoding="utf-8")
            summary_text = result.artifacts.summary_path.read_text(encoding="utf-8")
            report = json.loads(report_text)

            self.assertTrue(result.passed)
            self.assertEqual(report["schema_version"], EVAL_SCHEMA_VERSION)
            self.assertEqual(report["summary"]["case_count"], len(all_case_ids()))
            self.assertEqual(report["summary"]["failed"], 0)
            self.assertEqual(len(report["cases"]), len(all_case_ids()))
            self.assertIn("json_precision_loss_warn", summary_text)
            self.assertIn("PASS raw_socket_attempt", output.getvalue())
            self.assertNotIn("PRIVATE KEY", report_text)
            self.assertNotIn("PRIVATE KEY", events_text)
            self.assertNotIn("PRIVATE KEY", summary_text)

    def test_eval_can_run_selected_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)

            result = run_eval(
                out_dir=out_dir,
                name="selected-eval",
                case_ids=("json_precision_loss_warn",),
                output=io.StringIO(),
            )
            report = json.loads(result.artifacts.report_path.read_text(encoding="utf-8"))

            self.assertTrue(result.passed)
            self.assertEqual(report["summary"]["case_count"], 1)
            self.assertEqual(report["cases"][0]["id"], "json_precision_loss_warn")
            self.assertEqual(report["cases"][0]["observed_outcome"], "allowed")
            self.assertEqual(report["cases"][0]["observed_precision_losses"], 1)
            self.assertEqual(report["cases"][0]["observed_network_calls"], 1)


if __name__ == "__main__":
    unittest.main()

