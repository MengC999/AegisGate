from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.engine import SafetyEngine  # noqa: E402
from src.aegisguard.policy import KeywordLibrary  # noqa: E402


class KeywordManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aegis-keywords-")
        self.path = Path(self.temporary.name) / "keywords.json"
        self.path.write_text(
            (ROOT / "data" / "keyword_library_v2.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.library = KeywordLibrary(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def digest(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_add_duplicate_remove_and_persistence(self) -> None:
        self.assertTrue(self.library.add("advertising", "星河 优惠码"))
        self.assertFalse(self.library.add("fraud", "星河优惠码"))
        persisted = KeywordLibrary(self.path)
        self.assertIn("星河 优惠码", persisted.categories()["fraud"]["terms"])
        self.assertTrue(persisted.remove("advertising", "星河优惠码"))
        self.assertFalse(persisted.remove("fraud", "星河优惠码"))

    def test_add_is_immediately_visible_to_detection(self) -> None:
        engine = SafetyEngine(ROOT)
        engine.keywords = self.library
        text = "青檀代号仅用于本次回归"
        before = engine.detect(text)
        self.assertFalse(any(item.source == "keyword" for item in before.evidence))
        self.assertTrue(self.library.add("violence", "青檀代号", score=0.9))
        after = engine.detect(text)
        self.assertTrue(
            any(
                item.source == "keyword" and item.category == "violence"
                for item in after.evidence
            )
        )
        self.assertEqual(after.action, "block")

    def test_valid_import_merges_once_and_reports_duplicates(self) -> None:
        result = self.library.import_data(
            {
                "categories": {
                    "advertising": {
                        "score": 0.58,
                        "terms": ["新客礼", "新 客礼", "加 微信"],
                    },
                    "sensitive_speech": ["越权暗语"],
                }
            }
        )
        self.assertEqual(result, {"added": 2, "duplicates": 2})
        categories = self.library.categories()
        self.assertIn("新客礼", categories["fraud"]["terms"])
        self.assertIn("越权暗语", categories["sensitive_speech"]["terms"])

    def test_invalid_import_never_changes_original_file(self) -> None:
        before = self.digest()
        with self.assertRaisesRegex(TypeError, "terms 必须是数组"):
            self.library.import_data(
                {
                    "categories": {
                        "advertising": ["会被回滚的词"],
                        "violence": {"score": 0.9, "terms": "非法字符串"},
                    }
                }
            )
        self.assertEqual(self.digest(), before)
        self.assertNotIn("会被回滚的词", self.path.read_text(encoding="utf-8"))

    def test_category_score_term_and_format_validation(self) -> None:
        invalid_payloads = [
            {"categories": {"unknown": ["词条"]}},
            {"categories": {"sexual": {"score": 1.2, "terms": ["词条"]}}},
            {"categories": {"sexual": {"score": True, "terms": ["词条"]}}},
            {"categories": {"sexual": {"terms": [123]}}},
            {"categories": {"sexual": {"terms": ["\n"]}}},
            {"categories": {"sexual": {"terms": [], "extra": "field"}}},
            {"categories": {"sexual": ["词条"]}, "unexpected": True},
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                before = self.digest()
                with self.assertRaises((TypeError, ValueError)):
                    self.library.import_data(payload)
                self.assertEqual(self.digest(), before)

        bad_json = Path(self.temporary.name) / "bad.json"
        bad_json.write_text("{not-json", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            self.library.import_file(bad_json)


if __name__ == "__main__":
    unittest.main()
