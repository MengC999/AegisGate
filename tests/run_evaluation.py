#!/usr/bin/env python3
"""Reproducible functional, robustness, temporal and end-to-end evaluation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.service import ConversationService  # noqa: E402
from src.aegisguard.llm import LLMClient  # noqa: E402


REPORTS = ROOT / "reports"
DATASETS = {
    "single_text": ROOT / "data" / "evaluation_cases_v2.json",
    "conversation_flow": ROOT / "data" / "conversation_test_cases_v2.json",
    "sequence": ROOT / "data" / "sequence_evaluation_cases_v3.json",
    "robustness": ROOT / "data" / "robustness_cases_v3.json",
}


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def wilson_interval(successes: int, total: int, z: float = 1.96) -> dict[str, float]:
    if total <= 0:
        return {"low": 0.0, "high": 0.0}
    ratio = successes / total
    denominator = 1 + z * z / total
    centre = (ratio + z * z / (2 * total)) / denominator
    spread = z * math.sqrt((ratio * (1 - ratio) + z * z / (4 * total)) / total) / denominator
    return {"low": round(max(0.0, centre - spread), 4), "high": round(min(1.0, centre + spread), 4)}


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_cases(name: str) -> list[dict[str, Any]]:
    value = json.loads(DATASETS[name].read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise TypeError(f"{DATASETS[name].name} 顶层必须是数组")
    return value


def binary_metrics(counter: Counter[str]) -> dict[str, Any]:
    precision = counter["tp"] / max(1, counter["tp"] + counter["fp"])
    recall = counter["tp"] / max(1, counter["tp"] + counter["fn"])
    f1 = 2 * precision * recall / max(0.000001, precision + recall)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "confusion": {key: counter[key] for key in ("tp", "fp", "fn", "tn")},
    }


def evaluate(
    runtime_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    service = ConversationService(
        ROOT,
        llm=LLMClient(ROOT / "tests" / "fixtures" / "mock_api_config.json"),
        runtime_dir=runtime_dir,
    )
    rows: list[dict[str, Any]] = []
    trace_samples: list[dict[str, Any]] = []

    binary: Counter[str] = Counter()
    latencies: list[float] = []
    group_totals: Counter[str] = Counter()
    group_passed: Counter[str] = Counter()
    threshold_inputs: list[tuple[int, bool]] = []

    single_cases = load_cases("single_text")
    for case in single_cases:
        decision = service.engine.detect(case["text"], case["direction"])
        action_ok = decision.action == case["expected_action"]
        required = set(case.get("expected_categories", []))
        category_ok = required.issubset(decision.categories)
        passed = action_ok and category_ok
        expected_positive = case["expected_action"] != "pass"
        actual_positive = decision.action != "pass"
        if expected_positive and actual_positive:
            binary["tp"] += 1
        elif not expected_positive and actual_positive:
            binary["fp"] += 1
        elif expected_positive and not actual_positive:
            binary["fn"] += 1
        else:
            binary["tn"] += 1
        threshold_inputs.append((decision.risk_score, expected_positive))
        latencies.append(decision.latency_ms)
        group_totals[case["group"]] += 1
        group_passed[case["group"]] += int(passed)
        rows.append(
            {
                "suite": "single_text", "id": case["id"], "group": case["group"], "direction": case["direction"],
                "expected_action": case["expected_action"], "actual_action": decision.action,
                "expected_categories": ",".join(sorted(required)), "actual_categories": ",".join(decision.categories),
                "risk_score": decision.risk_score, "latency_ms": round(decision.latency_ms, 3), "passed": passed,
            }
        )
        if case["id"] in {"EV012", "EV029"}:
            trace_samples.append({"suite": "single_text", "id": case["id"], "explanation": decision.explanation})

    flow_rows: list[dict[str, Any]] = []
    for case in load_cases("conversation_flow"):
        result = service.process(case["input"], mock_output=case.get("mock_output"))
        passed = result.action == case["expected_action"]
        row = {
            "suite": "conversation_flow", "id": case["id"], "group": "flow",
            "expected_action": case["expected_action"], "actual_action": result.action,
            "risk_score": max(result.input_decision.risk_score, result.output_decision.risk_score if result.output_decision else 0),
            "latency_ms": round(result.latency_ms, 3), "passed": passed,
        }
        flow_rows.append(row)
        rows.append(row)

    sequence_rows: list[dict[str, Any]] = []
    for case in load_cases("sequence"):
        decision, analysis = service.engine.detect_sequence(case["turns"], case["direction"])
        required = set(case.get("expected_categories", []))
        passed = (
            decision.action == case["expected_action"]
            and required.issubset(decision.categories)
            and analysis["correlated"] == case["expected_correlated"]
        )
        row = {
            "suite": "sequence", "id": case["id"], "group": case["group"], "direction": case["direction"],
            "expected_action": case["expected_action"], "actual_action": decision.action,
            "expected_categories": ",".join(sorted(required)), "actual_categories": ",".join(decision.categories),
            "expected_correlated": case["expected_correlated"], "actual_correlated": analysis["correlated"],
            "risk_score": decision.risk_score, "risk_before": analysis["risk_before"], "risk_after": analysis["risk_after"],
            "turn_count": analysis["turn_count"], "latency_ms": round(decision.latency_ms, 3), "passed": passed,
        }
        sequence_rows.append(row)
        rows.append(row)
        if case["id"] in {"SQ001", "SQ015"}:
            trace_samples.append(
                {"suite": "sequence", "id": case["id"], "analysis": analysis, "explanation": decision.explanation}
            )

    robustness_rows: list[dict[str, Any]] = []
    stable_actions = 0
    for case in load_cases("robustness"):
        base = service.engine.detect(case["base_text"], case["direction"])
        variant = service.engine.detect(case["variant_text"], case["direction"])
        required = set(case.get("expected_categories", []))
        stable_action = base.action == variant.action
        stable_actions += int(stable_action)
        passed = (
            variant.action == case["expected_action"]
            and required.issubset(variant.categories)
            and stable_action
        )
        row = {
            "suite": "robustness", "id": case["id"], "group": case["group"], "direction": case["direction"],
            "expected_action": case["expected_action"], "base_action": base.action, "actual_action": variant.action,
            "expected_categories": ",".join(sorted(required)), "actual_categories": ",".join(variant.categories),
            "stable_action": stable_action, "risk_score": variant.risk_score,
            "latency_ms": round(variant.latency_ms, 3), "passed": passed,
        }
        robustness_rows.append(row)
        rows.append(row)

    single_passed = sum(bool(row["passed"]) for row in rows if row["suite"] == "single_text")
    flow_passed = sum(bool(row["passed"]) for row in flow_rows)
    sequence_passed = sum(bool(row["passed"]) for row in sequence_rows)
    robustness_passed = sum(bool(row["passed"]) for row in robustness_rows)
    total_passed = sum(bool(row["passed"]) for row in rows)
    metrics: dict[str, Any] = {
        "evaluation_version": "3.0.0",
        "scope_notice": "结果仅适用于列明的自建小规模合成与受控测试集，不代表开放环境准确率。",
        "datasets": {
            name: {"file": path.relative_to(ROOT).as_posix(), "sha256": file_digest(path), "cases": len(load_cases(name))}
            for name, path in DATASETS.items()
        },
        "single_text": {
            "total": len(single_cases), "passed": single_passed,
            "accuracy": round(single_passed / len(single_cases), 4),
            "accuracy_wilson_95": wilson_interval(single_passed, len(single_cases)),
            **binary_metrics(binary),
            "latency_ms": {
                "mean": round(statistics.mean(latencies), 3),
                "p50": round(percentile(latencies, .5), 3),
                "p95": round(percentile(latencies, .95), 3),
            },
            "by_group": {
                key: {"passed": group_passed[key], "total": value, "accuracy": round(group_passed[key] / value, 4)}
                for key, value in sorted(group_totals.items())
            },
        },
        "conversation_flow": {
            "total": len(flow_rows), "passed": flow_passed, "accuracy": round(flow_passed / len(flow_rows), 4),
            "accuracy_wilson_95": wilson_interval(flow_passed, len(flow_rows)),
        },
        "sequence": {
            "total": len(sequence_rows), "passed": sequence_passed, "accuracy": round(sequence_passed / len(sequence_rows), 4),
            "accuracy_wilson_95": wilson_interval(sequence_passed, len(sequence_rows)),
            "correlated_cases": sum(bool(row["expected_correlated"]) for row in sequence_rows),
        },
        "robustness": {
            "total": len(robustness_rows), "passed": robustness_passed,
            "accuracy": round(robustness_passed / len(robustness_rows), 4),
            "accuracy_wilson_95": wilson_interval(robustness_passed, len(robustness_rows)),
            "action_stability": round(stable_actions / len(robustness_rows), 4),
        },
        "controlled_overall": {
            "total": len(rows), "passed": total_passed, "accuracy": round(total_passed / len(rows), 4),
            "accuracy_wilson_95": wilson_interval(total_passed, len(rows)),
        },
        "failures": [
            {
                key: row.get(key)
                for key in (
                    "suite",
                    "id",
                    "expected_action",
                    "actual_action",
                    "expected_categories",
                    "actual_categories",
                    "expected_correlated",
                    "actual_correlated",
                )
                if key in row
            }
            for row in rows
            if not row["passed"]
        ],
        "audit_integrity": service.audit.verify(),
    }

    threshold_curve: list[dict[str, Any]] = []
    for threshold in (20, 35, 45, 58, 65, 70, 78, 82, 90):
        counts: Counter[str] = Counter()
        for score, expected_positive in threshold_inputs:
            actual_positive = score >= threshold
            if expected_positive and actual_positive:
                counts["tp"] += 1
            elif not expected_positive and actual_positive:
                counts["fp"] += 1
            elif expected_positive and not actual_positive:
                counts["fn"] += 1
            else:
                counts["tn"] += 1
        threshold_curve.append({"threshold": threshold, **binary_metrics(counts)})
    return rows, metrics, threshold_curve, trace_samples


def write_reports(
    rows: list[dict[str, Any]],
    metrics: dict[str, Any],
    threshold_curve: list[dict[str, Any]],
    trace_samples: list[dict[str, Any]],
) -> None:
    REPORTS.mkdir(exist_ok=True)
    with (REPORTS / "evaluation_results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fields = sorted({key for row in rows for key in row})
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    with (REPORTS / "threshold_curve.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        flattened = []
        for row in threshold_curve:
            flattened.append({
                "threshold": row["threshold"], "precision": row["precision"], "recall": row["recall"], "f1": row["f1"],
                **row["confusion"],
            })
        writer = csv.DictWriter(handle, fieldnames=["threshold", "tp", "fp", "fn", "tn", "precision", "recall", "f1"])
        writer.writeheader()
        writer.writerows(flattened)
    (REPORTS / "evaluation_metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    (REPORTS / "decision_trace_samples.json").write_text(json.dumps(trace_samples, ensure_ascii=False, indent=2), encoding="utf-8")

    single = metrics["single_text"]
    flow = metrics["conversation_flow"]
    sequence = metrics["sequence"]
    robustness = metrics["robustness"]
    overall = metrics["controlled_overall"]
    markdown = "\n".join([
        "# 自动化测试结果", "", "本报告由 `python tests/run_evaluation.py` 自动生成。", "",
        "> 结果仅适用于本项目自建的小规模合成与受控测试集，不代表开放环境准确率或生产效果。", "",
        "| 测试面 | 结果 | 95% Wilson 区间 |", "|---|---:|---:|",
        f"| 单段动作与类别 | {single['passed']} / {single['total']} ({single['accuracy']:.2%}) | {single['accuracy_wilson_95']['low']:.2%}–{single['accuracy_wilson_95']['high']:.2%} |",
        f"| 双向流程 | {flow['passed']} / {flow['total']} ({flow['accuracy']:.2%}) | {flow['accuracy_wilson_95']['low']:.2%}–{flow['accuracy_wilson_95']['high']:.2%} |",
        f"| 多轮时序 | {sequence['passed']} / {sequence['total']} ({sequence['accuracy']:.2%}) | {sequence['accuracy_wilson_95']['low']:.2%}–{sequence['accuracy_wilson_95']['high']:.2%} |",
        f"| 变形鲁棒性 | {robustness['passed']} / {robustness['total']} ({robustness['accuracy']:.2%}) | {robustness['accuracy_wilson_95']['low']:.2%}–{robustness['accuracy_wilson_95']['high']:.2%} |",
        f"| 受控用例合计 | {overall['passed']} / {overall['total']} ({overall['accuracy']:.2%}) | {overall['accuracy_wilson_95']['low']:.2%}–{overall['accuracy_wilson_95']['high']:.2%} |",
        "", "## 补充指标", "",
        f"- 单段违规识别 Precision / Recall / F1：{single['precision']:.4f} / {single['recall']:.4f} / {single['f1']:.4f}",
        f"- 单段 P95 检测延迟：{single['latency_ms']['p95']} ms",
        f"- 变形用例动作稳定率：{robustness['action_stability']:.2%}",
        f"- 审计链校验：{'通过' if metrics['audit_integrity']['valid'] else '失败'}",
        "", "数据集摘要、逐条明细、阈值曲线与匿名决策轨迹分别见同目录 JSON/CSV 文件。", "",
    ])
    (REPORTS / "自动化测试报告.md").write_text(markdown, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="运行 AegisGate 受控功能评测")
    parser.add_argument("--no-write", action="store_true", help="不更新 reports 中的正式评测文件")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aegis-controlled-evaluation-") as temporary:
        rows, metrics, threshold_curve, trace_samples = evaluate(Path(temporary))
    if not args.no_write:
        write_reports(rows, metrics, threshold_curve, trace_samples)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    suites = ("single_text", "conversation_flow", "sequence", "robustness")
    success = all(metrics[name]["passed"] == metrics[name]["total"] for name in suites)
    success = success and metrics["audit_integrity"]["valid"]
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
