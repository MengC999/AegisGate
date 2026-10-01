from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.evaluate_onnx_classifier import intervention_metrics  # noqa: E402
from scripts.semantic_model_common import classification_metrics, sha256  # noqa: E402


MODEL_DIR = ROOT / "models" / "official_four_onnx_v2"
DATA_DIR = ROOT / "data" / "semantic_classifier_v2"
REPORT = ROOT / "reports" / "semantic_model_evaluation_v2.json"


class SemanticModelV2ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_report_hashes_match_sealed_artifacts(self) -> None:
        self.assertEqual(
            self.report["dataset"]["manifest_sha256"],
            sha256(DATA_DIR / "dataset_manifest.json"),
        )
        self.assertEqual(
            self.report["dataset"]["test_data_sha256"],
            sha256(DATA_DIR / "test.jsonl"),
        )
        self.assertEqual(
            self.report["model"]["model_sha256"],
            sha256(MODEL_DIR / "model.onnx"),
        )
        self.assertEqual(self.report["model"]["model_bytes"], 154006588)
        self.assertEqual(self.report["model"]["execution_provider"], "CPUExecutionProvider")

    def test_report_metrics_recompute_from_anonymous_details(self) -> None:
        details = self.report["details"]
        expected = [item["expected"] for item in details]
        predicted = [item["predicted"] for item in details]
        thresholded = [item["evidence_label"] for item in details]
        gateway_interventions = [item["gateway_action"] != "pass" for item in details]
        self.assertEqual(classification_metrics(expected, predicted), self.report["raw_classifier"])
        self.assertEqual(
            classification_metrics(expected, thresholded),
            self.report["thresholded_evidence"]["classification"],
        )
        self.assertEqual(
            intervention_metrics(expected, gateway_interventions),
            self.report["end_to_end_gateway"]["binary"],
        )

    def test_sensitive_speech_recall_improves_over_frozen_v1_baseline(self) -> None:
        raw = self.report["raw_classifier"]
        thresholded = self.report["thresholded_evidence"]["classification"]
        self.assertEqual(raw["samples"], 250)
        self.assertGreater(raw["per_class"]["sensitive_speech"]["recall"], 0.4)
        self.assertGreater(thresholded["per_class"]["sensitive_speech"]["recall"], 0.4)

    def test_training_lineage_and_upstream_license_are_recorded(self) -> None:
        training = json.loads((MODEL_DIR / "training_summary.json").read_text(encoding="utf-8"))
        source = json.loads((MODEL_DIR / "SOURCE.json").read_text(encoding="utf-8"))
        self.assertEqual(training["dataset_id"], "aegisgate-official-four-v2")
        self.assertEqual(training["test_rows_used_during_training"], 0)
        self.assertEqual(source["base_model"], "hfl/rbt3")
        self.assertEqual(
            source["revision"],
            "0aa0527ff4170f29e1dfd3eb6ef60dc67e1bf75c",
        )
        self.assertEqual(source["upstream_license"], "Apache-2.0")


if __name__ == "__main__":
    unittest.main()
