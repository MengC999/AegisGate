from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

from scripts.delivery_preflight import run  # noqa: E402
from scripts.build_delivery_package import archive_paths  # noqa: E402


class DeliveryPreflightTests(unittest.TestCase):
    def test_preflight_does_not_read_or_package_env_local(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegis-preflight-") as temporary:
            root = Path(temporary)
            for relative in (
                "src",
                "web",
                "config",
                "data",
                "models/official_four_onnx_v2",
                "tests",
            ):
                (root / relative).mkdir(parents=True, exist_ok=True)
            (root / "README.md").write_text("safe", encoding="utf-8")
            (root / "requirements.txt").write_text("", encoding="utf-8")
            (root / "requirements-models.txt").write_text("", encoding="utf-8")
            (root / "requirements-training.txt").write_text("", encoding="utf-8")
            (root / ".env.local").write_text("secret marker", encoding="utf-8")
            (root / ".pytest_cache").mkdir()
            (root / ".pytest_cache" / "secret.txt").write_text("secret marker", encoding="utf-8")

            result = run(root)

            self.assertEqual(result["status"], "fail")
            self.assertIn(".env.local", result["forbidden_paths"])
            self.assertTrue(any(path == ".pytest_cache" for path in result["forbidden_paths"]))
            self.assertEqual(result["secret_hits"], [])
            self.assertNotIn(".env.local", [
                path for path in result.get("safe_paths", [])
            ])

    def test_current_project_preflight_reports_only_expected_manifest_staleness(self) -> None:
        result = run(ROOT)
        self.assertEqual(result["required_missing"], [])
        self.assertEqual(result["model_assets"]["status"], "ready")
        self.assertEqual(result["secret_hits"], [])
        self.assertIn(result["manifest"]["status"], {"stale", "ready"})

    def test_archive_paths_exclude_secret_and_runtime_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegis-archive-") as temporary:
            root = Path(temporary)
            (root / "keep.txt").write_text("safe", encoding="utf-8")
            (root / "MANIFEST.sha256").write_text("hash  keep.txt\n", encoding="utf-8")
            (root / ".env.local").write_text("secret", encoding="utf-8")
            (root / "runtime").mkdir()
            (root / "runtime" / "audit.jsonl").write_text("audit", encoding="utf-8")
            (root / ".venv").mkdir()
            (root / ".venv" / "secret.txt").write_text("secret", encoding="utf-8")
            names = {name for _, name in archive_paths(root)}
            self.assertEqual(names, {"keep.txt", "MANIFEST.sha256"})

    def test_git_metadata_is_excluded_without_blocking_a_cloned_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegis-git-source-") as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text(
                "https://test:credential@example.invalid/repository", encoding="utf-8"
            )
            (root / "README.md").write_text("safe", encoding="utf-8")
            result = run(root)
            self.assertEqual(result["forbidden_paths"], [])
            self.assertEqual(result["secret_hits"], [])
            self.assertEqual({name for _, name in archive_paths(root)}, {"README.md"})


if __name__ == "__main__":
    unittest.main()
