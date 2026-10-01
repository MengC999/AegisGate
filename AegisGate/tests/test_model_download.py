import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import download_models


class ModelDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "models").mkdir()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.content = b"test-only-pinned-model"
        self.record = {"asset": "v2.onnx", "path": "models/v2/model.onnx",
                       "bytes": len(self.content), "sha256": hashlib.sha256(self.content).hexdigest()}
        self.write_manifest()
        (self.assets / "v2.onnx").write_bytes(self.content)
        self.target = self.root / self.record["path"]
        self.patch = patch.object(download_models, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def write_manifest(self):
        (self.root / "models/downloads.json").write_text(json.dumps({"models": {"v2": self.record}}))

    def test_verified_install_and_offline_repeat(self):
        self.assertIn("installed", download_models.install("v2", self.assets))
        self.assertEqual(self.target.read_bytes(), self.content)
        with patch.object(download_models.urllib.request, "urlopen", side_effect=AssertionError("Unexpected network")):
            self.assertIn("verified", download_models.install("v2"))
            self.assertIn("verified", download_models.install("v2", verify_only=True))

    def test_bad_hash_preserves_existing_file_and_cleans_temporary(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"previous-model")
        (self.assets / "v2.onnx").write_bytes(b"X" * len(self.content))
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            download_models.install("v2", self.assets, force=True)
        self.assertEqual(self.target.read_bytes(), b"previous-model")
        self.assertEqual(list(self.target.parent.glob("*.tmp")), [])

    def test_oversized_asset_never_installed(self):
        (self.assets / "v2.onnx").write_bytes(self.content + b"extra")
        with self.assertRaisesRegex(ValueError, "exceeds"):
            download_models.install("v2", self.assets)
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.target.parent.glob("*.tmp")), [])

    def test_verify_only_never_downloads(self):
        with patch.object(download_models.urllib.request, "urlopen", side_effect=AssertionError("Unexpected network")):
            with self.assertRaisesRegex(ValueError, "missing"):
                download_models.install("v2", verify_only=True)

    def test_destination_escape_is_rejected(self):
        self.record["path"] = "../escaped.onnx"
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "inside models"):
            download_models.install("v2", self.assets)


if __name__ == "__main__":
    unittest.main()
