#!/usr/bin/env python3
"""Build a deterministic, preflighted ZIP only when explicitly requested."""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable


# Keep an in-place packaging run from adding Python cache files to staging.
sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import build_manifest  # noqa: E402
from scripts.delivery_preflight import run as run_preflight  # noqa: E402


def archive_paths(source: Path, output: Path | None = None) -> Iterable[tuple[Path, str]]:
    """Yield safe source files and POSIX archive names without opening secrets."""
    for path in build_manifest._files(source):
        if output is not None and path.resolve() == output.resolve():
            continue
        relative = path.relative_to(source)
        if not build_manifest._excluded_file(relative):
            yield path, relative.as_posix()
    manifest = source / "MANIFEST.sha256"
    if manifest.is_file():
        yield manifest, "MANIFEST.sha256"


def build_package(source: Path, output: Path, force: bool = False) -> dict[str, Any]:
    source = source.resolve()
    output = output.resolve()
    if output == source:
        raise ValueError("输出压缩包不能与 source 目录相同")
    preflight = run_preflight(source, require_manifest=True)
    if preflight["status"] != "pass":
        raise ValueError("staging 预检未通过，拒绝生成交付包")
    if output.exists() and not force:
        raise FileExistsError("输出文件已存在；如需覆盖请显式使用 --force")
    output.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if force else "x"
    file_count = 0
    total_bytes = 0
    with zipfile.ZipFile(
        output,
        mode=mode,
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path, relative in archive_paths(source, output):
            info = zipfile.ZipInfo(relative, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            payload = path.read_bytes()
            archive.writestr(info, payload)
            file_count += 1
            total_bytes += len(payload)
    return {
        "status": "pass",
        "output": str(output),
        "file_count": file_count,
        "source_bytes": total_bytes,
        "archive_bytes": output.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="构建无密钥 AegisGate 交付 ZIP")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true", help="只运行严格预检，不写 ZIP")
    parser.add_argument("--force", action="store_true", help="允许覆盖已有输出 ZIP")
    args = parser.parse_args()
    source = args.source.resolve()
    if args.dry_run:
        result = run_preflight(source, require_manifest=True)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "pass" else 1
    try:
        result = build_package(source, args.output, force=args.force)
    except (FileExistsError, OSError, ValueError) as exc:
        print(json.dumps({"status": "fail", "reason": type(exc).__name__}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
