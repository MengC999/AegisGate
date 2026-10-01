#!/usr/bin/env python3
"""Run reproducible platform acceptance with the active Python interpreter."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.platform_support import collect_environment, missing_dependency_files  # noqa: E402


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "unknown"


def default_report(environment: dict[str, Any]) -> Path:
    system = environment["system"]
    name = f"platform_acceptance_{_safe_name(system['name'])}_{_safe_name(system['cpu_architecture'])}.json"
    return ROOT / "reports" / name


def run_step(name: str, arguments: list[str]) -> dict[str, Any]:
    print(f"\n[{name}] {' '.join(arguments)}")
    started = time.perf_counter()
    environment = os.environ.copy()
    environment.setdefault("PYTHONUTF8", "1")
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
    )
    print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    return {
        "name": name,
        "command": arguments,
        "exit_code": completed.returncode,
        "duration_seconds": round(time.perf_counter() - started, 3),
        "output": completed.stdout,
    }


def _step(steps: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    return next((item for item in steps if item["name"] == name), None)


def _last_nonempty_line(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _json_line(step: dict[str, Any] | None) -> dict[str, Any] | None:
    if step is None:
        return None
    try:
        value = json.loads(_last_nonempty_line(str(step["output"])))
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _test_count(steps: list[dict[str, Any]]) -> int | None:
    for step in steps:
        matches = re.findall(r"Ran\s+(\d+)\s+tests?", str(step["output"]))
        if matches:
            return int(matches[-1])
    return None


def _health_payload(step: dict[str, Any] | None) -> dict[str, Any] | None:
    if step is None:
        return None
    marker = "本地服务自检通过："
    for line in str(step["output"]).splitlines():
        if marker not in line:
            continue
        try:
            value = json.loads(line.split(marker, 1)[1])
        except (json.JSONDecodeError, IndexError):
            return None
        return value if isinstance(value, dict) else None
    return None


def _evaluation_summary(step: dict[str, Any] | None) -> dict[str, Any] | None:
    if step is None or step["exit_code"] != 0:
        return None
    report = ROOT / "reports" / "semantic_model_evaluation_v2_regression.json"
    try:
        payload = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    dataset = payload.get("dataset")
    model = payload.get("model")
    if not isinstance(dataset, dict) or not isinstance(model, dict):
        return None
    return {
        "evaluation_purpose": payload.get("evaluation_purpose"),
        "independent_holdout": payload.get("independent_holdout"),
        "dataset_id": dataset.get("dataset_id"),
        "dataset_version": dataset.get("dataset_version"),
        "manifest_sha256": dataset.get("manifest_sha256"),
        "test_data_sha256": dataset.get("test_data_sha256"),
        "test_samples": dataset.get("test_samples"),
        "model_status": model.get("status"),
        "model_sha256": model.get("model_sha256"),
        "model_bytes": model.get("model_bytes"),
        "execution_provider": model.get("execution_provider"),
        "raw_classifier": payload.get("raw_classifier"),
        "thresholded_evidence": payload.get("thresholded_evidence"),
        "end_to_end_gateway": payload.get("end_to_end_gateway"),
        "gateway_artifacts": payload.get("gateway_artifacts"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="执行 AegisGate 跨平台完整验收")
    parser.add_argument(
        "--strict-baseline",
        action="store_true",
        help="要求当前解释器必须为 Python 3.12",
    )
    parser.add_argument(
        "--deepseek-smoke",
        action="store_true",
        help="显式使用 DEEPSEEK_API_KEY 执行一次真实 DeepSeek Smoke Test",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="只运行语法、单元/API 测试和健康检查，不运行评测与基准",
    )
    parser.add_argument("--output", type=Path, help="覆盖默认 JSON 报告路径")
    args = parser.parse_args()

    environment = collect_environment(ROOT)
    python_info = environment["python"]
    missing_files = missing_dependency_files(environment)
    if args.quick:
        commands = [
            (
                "语法编译",
                [sys.executable, "-m", "compileall", "-q", "src", "scripts", "tests"],
            ),
            (
                "单元与 API 测试",
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests",
                    "-p",
                    "test_*.py",
                    "-v",
                ],
            ),
        ]
    else:
        commands = [("现有完整验收", [sys.executable, "scripts/acceptance.py"])]
    commands.append(("ONNX CPU Smoke Test", [sys.executable, "scripts/onnx_smoke_test.py"]))
    if not args.quick:
        commands.append(
            ("ONNX 独立测试集评测", [sys.executable, "scripts/evaluate_onnx_classifier.py"])
        )
    if args.deepseek_smoke:
        commands.append(
            ("DeepSeek 真实 Smoke Test", [sys.executable, "scripts/deepseek_smoke_test.py"])
        )
    commands.append(
        ("启动器健康检查", [sys.executable, "scripts/launch_demo.py", "--health-check"])
    )
    steps = [run_step(name, command) for name, command in commands]

    baseline_ok = python_info["baseline_match"] or not args.strict_baseline
    accepted = (
        python_info["runtime_supported"]
        and baseline_ok
        and not missing_files
        and all(step["exit_code"] == 0 for step in steps)
    )
    deepseek_step = _step(steps, "DeepSeek 真实 Smoke Test")
    payload = {
        "accepted": accepted,
        "strict_baseline": args.strict_baseline,
        "mode": "quick" if args.quick else "full",
        "environment": environment,
        "dependency_files_complete": not missing_files,
        "missing_dependency_files": missing_files,
        "steps": steps,
        "verification_summary": {
            "automatic_test_count": _test_count(steps),
            "local_model_runtime": environment["local_model_runtime"],
            "onnx_smoke": _json_line(_step(steps, "ONNX CPU Smoke Test")),
            "semantic_model_evaluation": _evaluation_summary(
                _step(steps, "ONNX 独立测试集评测")
            ),
            "health_check": _health_payload(_step(steps, "启动器健康检查")),
            "deepseek_smoke": {
                "requested": args.deepseek_smoke,
                "exit_code": deepseek_step["exit_code"] if deepseek_step else None,
                "result": _last_nonempty_line(str(deepseek_step["output"])) if deepseek_step else "not_run",
            },
        },
    }
    output = (args.output or default_report(environment)).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"\n平台验收: {'通过' if accepted else '失败'}")
    if args.strict_baseline and not python_info["baseline_match"]:
        print(
            f"当前 Python {python_info['version']} 不是正式基线 3.12；"
            "测试结果仅可作为兼容性证据。"
        )
    print(f"验收报告: {output}")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
