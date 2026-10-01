#!/usr/bin/env python3
"""Copy a filtered AegisGate delivery tree without reading excluded files."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import build_manifest  # noqa: E402


def stage(source: Path, destination: Path) -> tuple[int, int]:
    source = source.resolve()
    destination = destination.resolve()
    if source == destination or source in destination.parents:
        raise ValueError("交付目录必须位于源目录之外")
    destination.mkdir(parents=True, exist_ok=True)
    copied = 0
    byte_count = 0
    for path in build_manifest._files(source):
        relative = path.relative_to(source)
        if build_manifest._excluded_file(relative):
            continue
        target = destination / relative
        if target.exists():
            raise FileExistsError(f"目标文件已存在: {relative.as_posix()}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        copied += 1
        byte_count += target.stat().st_size
    return copied, byte_count


def main() -> int:
    parser = argparse.ArgumentParser(description="生成无密钥的 AegisGate 交付副本")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        copied, byte_count = stage(args.source, args.destination)
    except (FileExistsError, OSError, ValueError) as exc:
        print(f"交付副本生成失败：{type(exc).__name__}")
        return 1
    print(f"已复制 {copied} 个安全文件，共 {byte_count} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
