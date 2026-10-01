from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.semantic_model_common import (  # noqa: E402
    LABELS,
    classification_metrics,
    sha256,
    verify_dataset_manifest,
    verify_group_isolation,
)


DATA_DIR = ROOT / "data" / "semantic_classifier_v2"
MANIFEST = DATA_DIR / "dataset_manifest.json"
SEALED_MANIFEST_SHA256 = "8dcf591bf5e00abf1f3ea66c01570904778f19be845346bf64f9568cd41aed40"
SEALED_TEST_SHA256 = "a4effcb231e0dc6e1a4244bcff7faf37c9e4237e3c735af5f1953109cdc6e3cd"


class SemanticDatasetV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest, cls.rows, cls.manifest_sha256 = verify_dataset_manifest(
            MANIFEST,
            ("train", "validation", "test"),
            require_v2_metadata=True,
        )

    def test_sealed_hashes_counts_and_balanced_labels(self) -> None:
        self.assertEqual(self.manifest_sha256, SEALED_MANIFEST_SHA256)
        self.assertEqual(sha256(DATA_DIR / "test.jsonl"), SEALED_TEST_SHA256)
        self.assertEqual(
            {split: len(rows) for split, rows in self.rows.items()},
            {"train": 500, "validation": 100, "test": 250},
        )
        for split, rows in self.rows.items():
            expected = len(rows) // len(LABELS)
            self.assertEqual(
                {label: sum(row["label"] == label for row in rows) for label in LABELS},
                {label: expected for label in LABELS},
                split,
            )

    def test_family_and_source_batch_never_cross_splits(self) -> None:
        verify_group_isolation(self.rows)
        contaminated = {split: list(rows) for split, rows in self.rows.items()}
        duplicate_family = dict(contaminated["train"][0])
        duplicate_family["id"] = "deliberate-cross-split-leak"
        duplicate_family["split"] = "validation"
        contaminated["validation"].append(duplicate_family)
        with self.assertRaisesRegex(ValueError, "family_id"):
            verify_group_isolation(contaminated)

    def test_holdout_has_required_variants_and_hard_normal_discussions(self) -> None:
        test_rows = self.rows["test"]
        self.assertNotIn("legacy_v1", {row["variant_type"] for row in test_rows})
        for variant in ("standard", "colloquial", "typo_obfuscated", "mixed_language", "contextual"):
            self.assertEqual(sum(row["variant_type"] == variant for row in test_rows), 50)
        normal_rows = [row for row in test_rows if row["label"] == "normal"]
        hard_normal = [row for row in normal_rows if str(row["subtype"]).startswith("safe_")]
        self.assertGreaterEqual(len(hard_normal), 30)
        sensitive_subtypes = {
            row["subtype"]
            for row in test_rows
            if row["label"] == "sensitive_speech"
        }
        self.assertTrue(
            {
                "prompt_injection",
                "privacy_leak",
                "document_forgery",
                "hate",
                "self_harm",
                "misinformation",
                "cyber_abuse",
                "impersonation",
                "financial_evasion",
            }.issubset(sensitive_subtypes)
        )

    def test_modified_holdout_is_rejected_before_evaluation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegis-v2-integrity-") as temporary:
            copied = Path(temporary) / "semantic_classifier_v2"
            copied.mkdir()
            shutil.copyfile(MANIFEST, copied / MANIFEST.name)
            shutil.copyfile(DATA_DIR / "test.jsonl", copied / "test.jsonl")
            with (copied / "test.jsonl").open("a", encoding="utf-8") as handle:
                handle.write("{}\n")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                verify_dataset_manifest(
                    copied / MANIFEST.name,
                    ("test",),
                    require_v2_metadata=True,
                )

    def test_known_confusion_matrix_metrics_are_stable(self) -> None:
        expected = ["normal", "normal", "sexual", "violence", "advertising", "sensitive_speech"]
        predicted = ["normal", "sexual", "sexual", "sexual", "advertising", "normal"]
        metrics = classification_metrics(expected, predicted)
        self.assertEqual(metrics["samples"], 6)
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertEqual(metrics["violation_interception_rate"], 0.75)
        self.assertEqual(metrics["normal_false_positive_rate"], 0.5)
        self.assertEqual(
            metrics["confusion_matrix"]["rows_actual_columns_predicted"],
            [
                [1, 1, 0, 0, 0],
                [0, 1, 0, 0, 0],
                [0, 1, 0, 0, 0],
                [0, 0, 0, 1, 0],
                [1, 0, 0, 0, 0],
            ],
        )

    def test_manifest_records_reviewed_deduplication_and_lineage(self) -> None:
        deduplication = self.manifest["deduplication"]
        self.assertEqual(deduplication["exact_duplicates"], 0)
        self.assertEqual(deduplication["family_cross_split_leaks"], 0)
        self.assertEqual(deduplication["source_batch_cross_split_leaks"], 0)
        self.assertLess(
            max(
                (item["anchor_trigram_jaccard"] for item in deduplication["manual_review_top20"]),
                default=0.0,
            ),
            0.5,
        )
        self.assertIn("v1", self.manifest["legacy_policy"])
        self.assertEqual(self.manifest["license"], "CC-BY-4.0")

    def test_manual_near_duplicate_review_covers_every_candidate(self) -> None:
        review = json.loads(
            (DATA_DIR / "near_duplicate_review.json").read_text(encoding="utf-8")
        )
        candidates = self.manifest["deduplication"]["manual_review_top20"]
        expected = {(item["left"], item["right"]) for item in candidates}
        actual = {(item["left"], item["right"]) for item in review["items"]}
        self.assertEqual(actual, expected)
        self.assertEqual(review["summary"]["candidates"], len(candidates))
        self.assertEqual(review["summary"]["rejected_as_leakage"], 0)
        self.assertTrue(
            all(item["decision"] == "accepted_distinct" for item in review["items"])
        )


if __name__ == "__main__":
    unittest.main()
