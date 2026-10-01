from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.service import ConversationService  # noqa: E402


class BatchGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aegis-batch-")
        self.service = ConversationService(ROOT, runtime_dir=Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_batch_reuses_inference_but_audits_every_record(self) -> None:
        marker = "BATCH_RAW_MARKER"
        result = self.service.batch_detect(
            [
                {"id": "a", "text": "请整理会议纪要"},
                {"id": "b", "text": marker},
                {"id": "c", "text": marker},
            ]
        )
        summary = result["summary"]
        self.assertEqual(summary["total_records"], 3)
        self.assertEqual(summary["unique_texts"], 2)
        self.assertEqual(summary["deduplicated_records"], 1)
        self.assertEqual(len(result["items"]), 3)
        self.assertFalse(any(marker in json.dumps(item, ensure_ascii=False) for item in result["items"]))
        lines = (Path(self.temporary.name) / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(all("batch_id" in line for line in lines))

    def test_batch_can_return_only_safe_text_when_explicitly_requested(self) -> None:
        result = self.service.batch_detect(
            [{"id": "safe", "text": "请整理会议纪要"}], include_safe_text=True
        )
        item = result["items"][0]
        self.assertEqual(item["id"], "safe")
        self.assertIn("safe_text", item)

    def test_governance_status_is_content_free_and_hashes_configuration(self) -> None:
        status = self.service.governance_status()
        self.assertEqual(status["schema_version"], "1.0")
        self.assertEqual(status["privacy"]["raw_content_persisted"], False)
        self.assertRegex(status["policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(status["keyword_library_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("batch_governance_detection", status["capabilities"])

    def test_batch_limit_is_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "数量"):
            self.service.batch_detect([{"id": str(i), "text": "ok"} for i in range(501)])


if __name__ == "__main__":
    unittest.main()
