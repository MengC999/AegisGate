from __future__ import annotations

import json
import sys
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.semantic_model_common import sha256  # noqa: E402
from src.aegisguard.normalizer import normalize  # noqa: E402


DATA_DIR = ROOT / "data" / "e2e_holdout_v1"
DATASET = DATA_DIR / "test.jsonl"
MANIFEST = DATA_DIR / "dataset_manifest.json"
REPORT = ROOT / "reports" / "e2e_gateway_holdout_v1.json"


class E2EHoldoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows = [
            json.loads(line)
            for line in DATASET.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.report = json.loads(REPORT.read_text(encoding="utf-8"))

    def test_frozen_counts_metadata_and_hash(self) -> None:
        self.assertEqual(len(self.rows), 200)
        self.assertEqual(
            Counter(row["label"] for row in self.rows),
            Counter({
                "normal": 100,
                "sexual": 25,
                "violence": 25,
                "advertising": 25,
                "sensitive_speech": 25,
            }),
        )
        self.assertEqual(self.manifest["evaluation_use"], "frozen_final_holdout")
        self.assertEqual(self.manifest["license"], "CC-BY-4.0")
        self.assertEqual(self.manifest["files"]["test.jsonl"]["sha256"], sha256(DATASET))
        self.assertTrue(all(row["source"] for row in self.rows))
        self.assertTrue(all(row["annotation"] for row in self.rows))

    def test_no_normalized_duplicates_or_v2_overlap(self) -> None:
        compact = [normalize(row["text"]).compact for row in self.rows]
        self.assertEqual(len(compact), len(set(compact)))
        v2_compact: set[str] = set()
        for split in ("train", "validation", "test"):
            path = ROOT / "data" / "semantic_classifier_v2" / f"{split}.jsonl"
            v2_compact.update(
                normalize(json.loads(line)["text"]).compact
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        self.assertFalse(set(compact) & v2_compact)

    def test_report_is_independent_and_recomputes_binary_metrics(self) -> None:
        self.assertTrue(self.report["independent_holdout"])
        details = self.report["details"]
        expected = [item["label"] for item in details]
        actions = [item["action"] for item in details]
        counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for truth, action in zip(expected, actions):
            violation = truth != "normal"
            intervened = action != "pass"
            if violation and intervened:
                counts["tp"] += 1
            elif violation:
                counts["fn"] += 1
            elif intervened:
                counts["fp"] += 1
            else:
                counts["tn"] += 1
        self.assertEqual(self.report["binary"]["confusion"], counts)
        self.assertTrue(self.report["meets_competition_threshold"])
        self.assertGreaterEqual(self.report["binary"]["violation_interception_rate"], 0.90)
        self.assertLessEqual(self.report["binary"]["normal_false_positive_rate"], 0.05)


if __name__ == "__main__":
    unittest.main()
