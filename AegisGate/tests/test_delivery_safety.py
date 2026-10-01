from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]

from scripts import build_manifest  # noqa: E402


class DeliverySafetyTests(unittest.TestCase):
    def test_manifest_skips_secrets_environments_caches_and_runtime_data_before_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegis-manifest-") as temporary:
            root = Path(temporary)
            included = {
                "source.txt": "deliverable",
                ".env.example": "DEEPSEEK_API_KEY=\n",
                "runtime/README.md": "runtime documentation",
            }
            excluded = {
                ".env.local": "secret marker",
                ".env": "secret marker",
                ".env.production": "secret marker",
                ".venv/package.bin": "cache marker",
                ".venv-training/package.bin": "cache marker",
                "venv/package.bin": "cache marker",
                ".pytest_cache/state": "cache marker",
                "logs/access.log": "runtime marker",
                "runtime/audit.jsonl": "audit marker",
                "runtime/nested/README.md": "private runtime notes",
                ".git/config": "gitdir: private worktree path",
                "client.pem": "private material marker",
                "client.pfx": "private material marker",
                "client.key": "private material marker",
                "business.sqlite3": "runtime marker",
                "business.db-wal": "runtime marker",
                "business.db-shm": "runtime marker",
                "models/local.gguf": "external model marker",
                "models/local.safetensors": "external model marker",
                "reports/private.json": "private report marker",
                "reports/nested/README.md": "private report marker",
                "report.docx": "private report marker",
                "photo.jpg": "unlicensed image marker",
                "docs/patent/draft.md": "private material marker",
                "data/patent_eval/cases.json": "private material marker",
                "build/source.txt": "generated marker",
                "dist/source.txt": "generated marker",
                "render_check/page.png": "private image marker",
            }
            for relative, content in {**included, **excluded}.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            path_type = type(root)
            original_read_bytes = path_type.read_bytes
            read_paths: list[str] = []

            def recording_read_bytes(path: Path) -> bytes:
                read_paths.append(path.relative_to(root).as_posix())
                return original_read_bytes(path)

            previous_root = build_manifest.ROOT
            build_manifest.ROOT = root
            try:
                with patch.object(path_type, "read_bytes", recording_read_bytes):
                    paths = {relative for _, relative in build_manifest.entries()}
            finally:
                build_manifest.ROOT = previous_root

            self.assertEqual(paths, set(included))
            self.assertEqual(set(read_paths), set(included))

    def test_bat_hash_survives_git_line_ending_conversion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aegis-newline-") as temporary:
            path = Path(temporary) / "start.bat"
            path.write_bytes(b"@echo off\r\npython app.py\r\n")
            expected = build_manifest.file_digest(path)
            path.write_bytes(b"@echo off\npython app.py\n")
            self.assertEqual(build_manifest.file_digest(path), expected)


if __name__ == "__main__":
    unittest.main()
