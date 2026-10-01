#!/usr/bin/env python3
"""Install pinned ONNX assets, checking size and SHA-256 before replacement."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CHUNK = 1024 * 1024


def matches(path: Path, record: dict) -> bool:
    if not path.is_file() or path.stat().st_size != record["bytes"]:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest() == record["sha256"]


def install(version: str, source_dir: Path | None = None, *, force: bool = False,
            verify_only: bool = False) -> str:
    manifest = json.loads((ROOT / "models/downloads.json").read_text(encoding="utf-8"))
    record = manifest["models"][version]
    relative = Path(record["path"])
    target = (ROOT / relative).resolve()
    if relative.is_absolute() or not target.is_relative_to((ROOT / "models").resolve()):
        raise ValueError("Model destination must remain inside models/")
    if Path(record["asset"]).name != record["asset"]:
        raise ValueError("Invalid model asset filename")
    if matches(target, record):
        return f"{version}: verified"
    if verify_only:
        raise ValueError(f"{version}: model missing or checksum mismatch")
    if target.exists() and not force:
        raise ValueError(f"{version}: existing file invalid; use --force to replace it")
    target.parent.mkdir(parents=True, exist_ok=True)
    if source_dir is not None:
        stream = (source_dir / record["asset"]).open("rb")
    else:
        url = (f'https://github.com/{manifest["repository"]}/releases/download/'
               f'{manifest["release"]}/{record["asset"]}')
        request = urllib.request.Request(url, headers={"User-Agent": "AegisGate-model-installer/1.0"})
        stream = urllib.request.urlopen(request, timeout=60)
    temporary = None
    try:
        with stream, tempfile.NamedTemporaryFile(dir=target.parent, suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            size = 0
            for chunk in iter(lambda: stream.read(CHUNK), b""):
                size += len(chunk)
                if size > record["bytes"]:
                    raise ValueError(f"{version}: asset exceeds expected size")
                output.write(chunk)
        if not matches(temporary, record):
            raise ValueError(f"{version}: size or SHA-256 mismatch; destination preserved")
        temporary.replace(target)
        return f"{version}: installed and verified"
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=("v1", "v2", "all"), default="v2")
    parser.add_argument("--source-dir", type=Path, help="Use manually downloaded release assets")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--force", action="store_true", help="Replace an invalid local model after verifying its replacement")
    args = parser.parse_args()
    try:
        for version in (("v1", "v2") if args.model == "all" else (args.model,)):
            print(install(version, args.source_dir, force=args.force, verify_only=args.verify_only))
    except (OSError, ValueError, KeyError) as error:
        print(f"Model setup failed: {error}")
        print("Use official release assets with --source-dir if the download is unavailable.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
