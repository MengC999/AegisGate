#!/usr/bin/env python3
"""Validate a source ZIP without installing dependencies or downloading models."""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import build_manifest  # noqa: E402
from scripts.delivery_preflight import run  # noqa: E402


def verify_archive(archive_path: Path, expected_sha256: str | None = None) -> dict:
    digest = hashlib.sha256()
    with archive_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    actual_digest = digest.hexdigest()
    if expected_sha256 is not None and actual_digest != expected_sha256.lower():
        raise ValueError("Archive SHA-256 mismatch")
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) > 10000 or sum(item.file_size for item in entries) > 100 * 1024 * 1024:
            raise ValueError("Source archive exceeds expected size")
        seen: set[str] = set()
        for item in entries:
            name = item.filename
            path = PurePosixPath(name)
            if (not name or name.startswith("/") or "\\" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                    or path.is_absolute() or stat.S_ISLNK(item.external_attr >> 16)):
                raise ValueError("Unsafe archive path")
            folded = name.rstrip("/").casefold()
            if folded in seen:
                raise ValueError("Duplicate archive path")
            seen.add(folded)
            directories = path.parts if item.is_dir() else path.parts[:-1]
            if any(build_manifest._excluded_directory(part) for part in directories):
                raise ValueError("Excluded archive directory")
            if not item.is_dir() and name != "MANIFEST.sha256":
                if build_manifest._excluded_file(Path(name)):
                    raise ValueError("Excluded archive file")
        if archive.testzip() is not None:
            raise ValueError("ZIP CRC mismatch")
        with tempfile.TemporaryDirectory(prefix="aegis-source-verify-") as temporary:
            root = Path(temporary)
            archive.extractall(root)
            result = run(root, require_manifest=True)
            if result["status"] != "pass":
                raise ValueError("Source preflight failed: " + json.dumps({
                    key: result[key] for key in (
                        "required_missing", "forbidden_paths", "secret_hits", "manifest", "model_assets"
                    )
                }, ensure_ascii=False))
    return {"status": "pass", "files": sum(not item.is_dir() for item in entries),
            "archive_bytes": archive_path.stat().st_size, "sha256": actual_digest,
            "manifest_entries": result["manifest"]["entries"],
            "model_assets": result["model_assets"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--sha256", help="Compare against the separately supplied archive digest")
    args = parser.parse_args()
    try:
        result = verify_archive(args.archive, args.sha256)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        print(json.dumps({"status": "fail", "reason": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
