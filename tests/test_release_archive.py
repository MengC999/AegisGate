from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import build_manifest
from scripts.build_delivery_package import build_package
from scripts.delivery_preflight import run
from scripts.stage_delivery import stage
from scripts.verify_release import verify_archive

ROOT = Path(__file__).resolve().parents[1]


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aegis-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.archive = Path(self.temporary.name) / "source.zip"
        stage(ROOT, self.root)
        self.refresh_manifest()

    def refresh_manifest(self) -> None:
        with patch.object(build_manifest, "ROOT", self.root):
            entries = build_manifest.entries()
        (self.root / "MANIFEST.sha256").write_text(
            "".join(f"{digest}  {relative}\n" for digest, relative in entries),
            encoding="utf-8", newline="\n",
        )

    def test_clean_source_without_weights_can_be_verified_and_repackaged(self) -> None:
        self.assertFalse(list(self.root.rglob("*.onnx")))
        result = build_package(self.root, self.archive)
        verified = verify_archive(self.archive, hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(verified["files"], result["file_count"])
        self.assertEqual(verified["model_assets"]["status"], "external")
        self.assertEqual(verified["model_assets"]["missing_weights"], ["v1", "v2"])
        self.assertEqual(verified["model_assets"]["checked"], 14)

    def test_modified_source_fails_even_with_valid_zip_crc(self) -> None:
        (self.root / "README.md").write_text("modified", encoding="utf-8")
        with zipfile.ZipFile(self.archive, "w") as archive:
            for path in self.root.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(self.root).as_posix())
        with self.assertRaisesRegex(ValueError, "preflight failed"):
            verify_archive(self.archive)

    def test_rejects_private_files_and_path_traversal_before_extracting(self) -> None:
        for name in ("../escape.txt", "nested/../../escape.txt", "/absolute.txt",
                     "folder\\escape.txt", ".env.local", "private.pem",
                     "runtime/nested/README.md", "reports/private.json", "docs/patent/draft.md"):
            with self.subTest(name=name):
                with zipfile.ZipFile(self.archive, "w") as archive:
                    archive.writestr(name, "private marker")
                with self.assertRaises(ValueError):
                    verify_archive(self.archive)
        self.assertFalse((Path(self.temporary.name) / "escape.txt").exists())

    def test_rejects_case_collisions_and_wrong_archive_digest(self) -> None:
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("README.md", "one")
            archive.writestr("readme.md", "two")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            verify_archive(self.archive)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify_archive(self.archive, "0" * 64)

    def test_corrupt_metadata_blocks_release_even_after_source_manifest_refresh(self) -> None:
        (self.root / "models/official_four_onnx_v1/vocab.txt").write_text("corrupt", encoding="utf-8")
        self.refresh_manifest()
        result = run(self.root, require_manifest=True)
        self.assertEqual(result["manifest"]["status"], "ready")
        self.assertEqual(result["model_assets"]["status"], "invalid")
        self.assertEqual(result["status"], "fail")
        with self.assertRaises(ValueError):
            build_package(self.root, self.archive)

    def test_download_manifest_must_agree_with_model_checksums(self) -> None:
        path = self.root / "models/downloads.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["models"]["v2"]["sha256"] = "0" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(run(self.root)["model_assets"]["status"], "invalid")

    def test_corrupt_installed_weight_blocks_source_packaging(self) -> None:
        (self.root / "models/official_four_onnx_v2/model.onnx").write_bytes(b"broken model")
        self.assertEqual(run(self.root)["model_assets"]["status"], "invalid")
        with self.assertRaises(ValueError):
            build_package(self.root, self.archive)

    def test_source_starts_without_weights_or_site_packages(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-S", "-B", "scripts/launch_demo.py", "--health-check",
             "--runtime-dir", str(Path(self.temporary.name) / "runtime")],
            cwd=self.root, env=environment, capture_output=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        payload = json.loads(next(line[line.index("{"):] for line in completed.stdout.splitlines() if "{" in line))
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["model"]["provider"], "mock")
        self.assertEqual(payload["semantic_model"]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
