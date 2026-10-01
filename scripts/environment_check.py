#!/usr/bin/env python3
"""Record the local platform and validate the Python acceptance baseline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.platform_support import collect_environment, missing_dependency_files  # noqa: E402


DEFAULT_REPORT = ROOT / "reports" / "environment_check.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="检查并记录 AegisGate 跨平台运行环境")
    parser.add_argument(
        "--strict-baseline",
        action="store_true",
        help="要求当前解释器必须为统一验收基线 Python 3.12",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_REPORT,
        help="JSON 报告路径；相对路径按当前目录解析",
    )
    parser.add_argument("--no-write", action="store_true", help="只打印结果，不写报告")
    args = parser.parse_args()

    environment = collect_environment(ROOT)
    missing_files = missing_dependency_files(environment)
    payload = {
        **environment,
        "strict_baseline": args.strict_baseline,
        "dependency_files_complete": not missing_files,
        "missing_dependency_files": missing_files,
    }
    content = json.dumps(payload, ensure_ascii=False, indent=2)
    print(content)
    if not args.no_write:
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content + "\n", encoding="utf-8")
        print(f"环境报告: {output}")

    python_info = environment["python"]
    if not python_info["runtime_supported"] or missing_files:
        return 1
    if args.strict_baseline and not python_info["baseline_match"]:
        print("严格基线未通过：请使用 Python 3.12 重新执行。")
        return 2
    if not python_info["baseline_match"]:
        print(
            f"当前 Python {python_info['version']} 可用于兼容性检查，"
            "但不能记为 Python 3.12 正式基线验收。"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
