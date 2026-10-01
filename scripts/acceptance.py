#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "acceptance_report.json"


def run(name: str, arguments: list[str]) -> dict[str, object]:
    print(f"\n[{name}] {' '.join(arguments)}")
    started = time.perf_counter()
    result = subprocess.run(arguments, cwd=ROOT, check=False)
    return {"name": name, "command": arguments, "exit_code": result.returncode, "duration_seconds": round(time.perf_counter() - started, 3)}


def main() -> int:
    parser = argparse.ArgumentParser(description="执行 AegisGate 本地验收")
    parser.add_argument(
        "--refresh-auxiliary-model",
        action="store_true",
        help="显式重训并写入 Naive Bayes 辅助模型；默认验收不修改模型文件",
    )
    args = parser.parse_args()
    commands = [
        ("语法编译", [sys.executable, "-m", "compileall", "-q", "src", "scripts", "tests"]),
        ("单元与接口测试", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"]),
        ("功能评测", [sys.executable, "tests/run_evaluation.py"]),
        ("并发基准", [sys.executable, "tests/run_benchmark.py", "--iterations", "1000", "--workers", "8"]),
    ]
    if args.refresh_auxiliary_model:
        commands.insert(1, ("模型复训", [sys.executable, "scripts/train_classifier.py"]))
    results = [run(name, command) for name, command in commands]
    passed = all(item["exit_code"] == 0 for item in results)
    payload = {
        "accepted": passed,
        "python": sys.version,
        "refresh_auxiliary_model": args.refresh_auxiliary_model,
        "steps": results,
    }
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n验收结果: {'通过' if passed else '失败'}")
    print(f"报告: {REPORT}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
