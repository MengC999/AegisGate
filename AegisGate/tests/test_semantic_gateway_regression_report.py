from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.evaluate_onnx_classifier import intervention_metrics  # noqa: E402
from scripts.semantic_model_common import sha256  # noqa: E402


REPORT = ROOT / "reports" / "semantic_model_evaluation_v2_regression.json"


class SemanticGatewayRegressionReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_report_is_explicitly_non_independent_regression(self) -> None:
        self.assertEqual(self.report["evaluation_purpose"], "post_fix_regression")
        self.assertFalse(self.report["independent_holdout"])
        self.assertIn("不是新的独立盲测", self.report["scope_notice"])

    def test_report_matches_current_gateway_artifacts(self) -> None:
        artifacts = self.report["gateway_artifacts"]
        self.assertEqual(
            artifacts["engine_sha256"],
            sha256(ROOT / "src" / "aegisguard" / "engine.py"),
        )
        self.assertEqual(
            artifacts["policy_sha256"],
            sha256(ROOT / "config" / "safety_policy.json"),
        )
        self.assertEqual(
            artifacts["keyword_library_sha256"],
            sha256(ROOT / "data" / "keyword_library_v2.json"),
        )

    def test_gateway_binary_metrics_recompute_from_details(self) -> None:
        details = self.report["details"]
        expected = [item["expected"] for item in details]
        interventions = [item["gateway_action"] != "pass" for item in details]
        self.assertEqual(
            intervention_metrics(expected, interventions),
            self.report["end_to_end_gateway"]["binary"],
        )


if __name__ == "__main__":
    unittest.main()
