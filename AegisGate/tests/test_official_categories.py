from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.categories import (  # noqa: E402
    INTERNAL_TO_OFFICIAL,
    OFFICIAL_CATEGORY_NAMES,
    OFFICIAL_CATEGORY_ORDER,
    official_category_payload,
    to_official_categories,
)
from src.aegisguard.engine import SafetyEngine  # noqa: E402


class OfficialCategoryTests(unittest.TestCase):
    def test_all_internal_categories_have_one_documented_official_mapping(self) -> None:
        self.assertEqual(
            INTERNAL_TO_OFFICIAL,
            {
                "sexual": "sexual",
                "violence": "violence",
                "fraud": "advertising",
                "sensitive_speech": "sensitive_speech",
                "self_harm": "sensitive_speech",
                "illegal": "sensitive_speech",
                "hate": "sensitive_speech",
                "pii": "sensitive_speech",
                "prompt_injection": "sensitive_speech",
                "misinformation": "sensitive_speech",
            },
        )
        payload = official_category_payload()
        self.assertEqual(tuple(item["code"] for item in payload), OFFICIAL_CATEGORY_ORDER)
        self.assertEqual(
            [item["name"] for item in payload],
            ["色情", "暴力", "广告", "敏感话术"],
        )
        self.assertTrue(all(item["definition"] for item in payload))

    def test_mapping_is_deduplicated_and_keeps_official_order(self) -> None:
        self.assertEqual(
            to_official_categories(
                ["prompt_injection", "fraud", "sexual", "pii", "violence", "fraud"]
            ),
            ["sexual", "violence", "advertising", "sensitive_speech"],
        )

    def test_decision_exposes_internal_and_official_categories(self) -> None:
        decision = SafetyEngine(ROOT).detect("加微信领取内部优惠。")
        payload = decision.to_dict()
        self.assertIn("fraud", payload["categories"])
        self.assertIn("advertising", payload["official_categories"])
        self.assertEqual(OFFICIAL_CATEGORY_NAMES["advertising"], "广告")

    def test_packaged_model_mapping_matches_runtime_mapping(self) -> None:
        labels = json.loads(
            (ROOT / "models" / "official_four_onnx_v2" / "labels.json").read_text(
                encoding="utf-8"
            )
        )
        mapping = labels["official_mapping"]
        self.assertEqual(mapping["sexual"]["engine_category"], "sexual")
        self.assertEqual(mapping["violence"]["engine_category"], "violence")
        self.assertEqual(mapping["advertising"]["engine_category"], "fraud")
        self.assertEqual(
            mapping["sensitive_speech"]["engine_category"],
            "sensitive_speech",
        )


if __name__ == "__main__":
    unittest.main()
