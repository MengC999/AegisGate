#!/usr/bin/env python3
"""Evaluate the frozen end-to-end gateway holdout without tuning."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aegisguard.engine import SafetyEngine  # noqa: E402
from scripts.semantic_model_common import LABELS, sha256  # noqa: E402


HOLDOUT_DIR = ROOT / "data" / "e2e_holdout_v1"
DEFAULT_DATASET = HOLDOUT_DIR / "test.jsonl"
DEFAULT_MANIFEST = HOLDOUT_DIR / "dataset_manifest.json"
DEFAULT_REPORT = ROOT / "reports" / "e2e_gateway_holdout_v1.json"
E2E_LABELS = ("normal", "sexual", "violence", "advertising", "sensitive_speech")


def _load_rows(dataset: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(dataset.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict) or not isinstance(row.get("text"), str):
            raise ValueError(f"数据行 {line_number} 无效")
        if row.get("label") not in E2E_LABELS:
            raise ValueError(f"数据行 {line_number} 标签不在官方五分类中")
        if row.get("direction") not in {"input", "output"}:
            raise ValueError(f"数据行 {line_number} direction 无效")
        rows.append(row)
    return rows


def _class_metrics(expected: list[str], predicted: list[str]) -> dict[str, Any]:
    matrix = {label: {item: 0 for item in E2E_LABELS} for label in E2E_LABELS}
    for truth, actual in zip(expected, predicted):
        matrix.setdefault(truth, {}).setdefault(actual, 0)
        matrix[truth][actual] += 1
    per_class: dict[str, dict[str, Any]] = {}
    for label in E2E_LABELS:
        tp = matrix[label].get(label, 0)
        fp = sum(matrix[other].get(label, 0) for other in E2E_LABELS if other != label)
        fn = sum(matrix[label].get(other, 0) for other in E2E_LABELS if other != label)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1e-12, precision + recall)
        per_class[label] = {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "support": sum(matrix[label].values()),
        }
    accuracy = sum(truth == actual for truth, actual in zip(expected, predicted)) / max(1, len(expected))
    macro_f1 = sum(item["f1"] for item in per_class.values()) / len(E2E_LABELS)
    return {
        "samples": len(expected),
        "accuracy": round(accuracy, 6),
        "macro_f1": round(macro_f1, 6),
        "per_class": per_class,
        "confusion_matrix": {
            "labels": list(E2E_LABELS),
            "rows_actual_columns_predicted": [
                [matrix[truth].get(predicted_label, 0) for predicted_label in E2E_LABELS]
                for truth in E2E_LABELS
            ],
        },
    }


def _binary_metrics(expected: list[str], actions: list[str]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for truth, action in zip(expected, actions):
        violation = truth != "normal"
        intervened = action != "pass"
        if violation and intervened:
            counts["tp"] += 1
        elif violation:
            counts["fn"] += 1
        elif intervened:
            counts["fp"] += 1
        else:
            counts["tn"] += 1
    precision = counts["tp"] / max(1, counts["tp"] + counts["fp"])
    recall = counts["tp"] / max(1, counts["tp"] + counts["fn"])
    f1 = 2 * precision * recall / max(1e-12, precision + recall)
    return {
        "samples": len(expected),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "violation_interception_rate": round(recall, 6),
        "normal_false_positive_rate": round(
            counts["fp"] / max(1, counts["fp"] + counts["tn"]), 6
        ),
        "confusion": {key: counts[key] for key in ("tp", "fp", "fn", "tn")},
    }


def _predicted_label(decision: Any) -> str:
    official = decision.official_categories
    if not official:
        return "normal" if decision.action == "pass" else "sensitive_speech"
    return official[0]


def evaluate(dataset: Path, manifest_path: Path) -> dict[str, Any]:
    rows = _load_rows(dataset)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("evaluation_use") != "frozen_final_holdout":
        raise ValueError("数据集未声明为 frozen_final_holdout")
    if manifest.get("files", {}).get("test.jsonl", {}).get("sha256") != sha256(dataset):
        raise ValueError("冻结集 SHA-256 校验失败")
    engine = SafetyEngine(ROOT)
    model_status = engine.semantic_model_status()
    if model_status.get("status") != "ready":
        raise RuntimeError(f"语义模型不可用: {model_status}")

    expected: list[str] = []
    predicted: list[str] = []
    actions: list[str] = []
    details: list[dict[str, Any]] = []
    by_direction: dict[str, dict[str, list[Any]]] = defaultdict(lambda: {"expected": [], "predicted": [], "actions": []})
    for row in rows:
        decision = engine.detect(row["text"], row["direction"])
        truth = str(row["label"])
        actual = _predicted_label(decision)
        expected.append(truth)
        predicted.append(actual)
        actions.append(decision.action)
        by_direction[row["direction"]]["expected"].append(truth)
        by_direction[row["direction"]]["predicted"].append(actual)
        by_direction[row["direction"]]["actions"].append(decision.action)
        details.append({
            "id": row["id"],
            "label": truth,
            "direction": row["direction"],
            "variant_type": row.get("variant_type"),
            "action": decision.action,
            "predicted_official_category": actual,
            "risk_score": decision.risk_score,
            "official_categories": decision.official_categories,
            "evidence_sources": sorted({item.source for item in decision.evidence}),
        })

    direction_metrics = {
        direction: {
            "classification": _class_metrics(values["expected"], values["predicted"]),
            "binary": _binary_metrics(values["expected"], values["actions"]),
        }
        for direction, values in sorted(by_direction.items())
    }
    binary = _binary_metrics(expected, actions)
    return {
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "evaluation_purpose": "frozen_final_holdout",
        "independent_holdout": True,
        "tuning_notice": "本报告只记录冻结集结果；该数据集未用于阈值、规则或融合调参。",
        "dataset": {
            "dataset_id": manifest.get("dataset_id"),
            "dataset_version": manifest.get("dataset_version"),
            "test_samples": len(rows),
            "test_data_sha256": sha256(dataset),
            "source": manifest.get("source"),
            "license": manifest.get("license"),
            "label_counts": dict(sorted(Counter(expected).items())),
        },
        "model": {
            "status": model_status,
            "backend": "onnxruntime-cpu",
            "execution_provider": "CPUExecutionProvider",
        },
        "classification": _class_metrics(expected, predicted),
        "binary": binary,
        "direction_metrics": direction_metrics,
        "meets_competition_threshold": (
            binary["violation_interception_rate"] >= 0.90
            and binary["normal_false_positive_rate"] <= 0.05
        ),
        "details": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="评测冻结端到端网关测试集")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    payload = evaluate(args.dataset.resolve(), args.manifest.resolve())
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "samples": payload["dataset"]["test_samples"],
        "violation_interception_rate": payload["binary"]["violation_interception_rate"],
        "normal_false_positive_rate": payload["binary"]["normal_false_positive_rate"],
        "meets_competition_threshold": payload["meets_competition_threshold"],
        "report": str(report),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
