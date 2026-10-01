from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.audit import AuditStore  # noqa: E402


class DailyStatsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aegis-stats-")
        self.store = AuditStore(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def append(
        self,
        timestamp: str,
        action: str,
        categories: list[str],
        latency_ms: float = 10.0,
    ) -> None:
        with patch("src.aegisguard.audit.time.strftime", return_value=timestamp):
            self.store.append(
                {
                    "request_id": f"request-{timestamp}-{action}",
                    "action": action,
                    "categories": categories,
                    "risk_score": 50,
                    "latency_ms": latency_ms,
                }
            )

    def test_stats_use_utc_plus_eight_natural_day_and_official_mapping(self) -> None:
        self.append("2026-08-17T15:59:59Z", "input_block", ["violence"])
        self.append(
            "2026-08-17T16:00:00Z",
            "input_block",
            ["sexual", "prompt_injection"],
        )
        self.append("2026-08-18T01:00:00Z", "output_mask", ["fraud"])
        self.append("2026-08-18T02:00:00Z", "pass", ["prompt_injection"])
        self.append("2026-08-18T03:00:00Z", "input_support", ["self_harm"])

        stats = self.store.stats("2026-08-18")
        self.assertEqual(stats["timezone"], "Asia/Shanghai")
        self.assertEqual(stats["total_requests"], 4)
        self.assertEqual(stats["violation_requests"], 3)
        self.assertEqual(
            stats["actions"],
            {"block": 1, "mask": 1, "review": 0, "pass": 1, "support": 1},
        )
        official = stats["official_categories"]
        self.assertEqual(official["sexual"]["count"], 1)
        self.assertEqual(official["violence"]["count"], 0)
        self.assertEqual(official["advertising"]["count"], 1)
        self.assertEqual(official["sensitive_speech"]["count"], 2)
        self.assertEqual(official["sensitive_speech"]["share"], 0.5)
        self.assertTrue(stats["audit_integrity"]["valid"])

    def test_invalid_date_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "YYYY-MM-DD"):
            self.store.stats("18-08-2026")

    def test_review_status_is_append_only_and_verifiable(self) -> None:
        digest = self.store.append(
            {
                "request_id": "a" * 32,
                "action": "review",
                "categories": ["fraud"],
                "risk_score": 64,
            }
        )
        self.assertTrue(self.store.update_review_status(digest, "reviewed"))
        reviews = self.store.pending_reviews()
        self.assertEqual(reviews[-1]["status"], "reviewed")
        verified = self.store.verify()
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["entries"], 2)


if __name__ == "__main__":
    unittest.main()
