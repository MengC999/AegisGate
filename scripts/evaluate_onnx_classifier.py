#!/usr/bin/env python3
"""Evaluate raw ONNX, thresholded Evidence, and the end-to-end gateway."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.semantic_model_common import (  # noqa: E402
    LABELS,
    classification_metrics,
    sha256,
    verify_dataset_manifest,
)
from src.aegisguard.engine import SafetyEngine  # noqa: E402
from src.aegisguard.onnx_classifier import PretrainedONNXClassifier  # noqa: E402


DEFAULT_MODEL_DIR = ROOT / "models" / "official_four_onnx_v2"
DEFAULT_DATA_DIR = ROOT / "data" / "semantic_classifier_v2"
DEFAULT_REPORT = ROOT / "reports" / "semantic_model_evaluation_v2_regression.json"
DEFAULT_EVIDENCE_THRESHOLD = 0.75


def intervention_metrics(expected: list[str], intervened: list[bool]) -> dict[str, Any]:
    if len(expected) != len(intervened) or not expected:
        raise ValueError("二分类评测长度不匹配或为空")
    counts: Counter[str] = Counter()
    for truth, actual in zip(expected, intervened):
        violation = truth != "normal"
        if violation and actual:
            counts["tp"] += 1
        elif violation:
            counts["fn"] += 1
        elif actual:
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
            counts["fp"] / max(1, counts["fp"] + counts["tn"]),
            6,
        ),
        "confusion": {key: counts[key] for key in ("tp", "fp", "fn", "tn")},
    }


def grouped_raw_metrics(
    rows: list[dict[str, Any]],
    predicted: list[str],
    field: str,
) -> dict[str, Any]:
    groups: dict[str, list[int]] = {}
    for index, row in enumerate(rows):
        groups.setdefault(str(row.get(field, "unspecified")), []).append(index)
    payload: dict[str, Any] = {}
    for group, indexes in sorted(groups.items()):
        expected_group = [str(rows[index]["label"]) for index in indexes]
        predicted_group = [predicted[index] for index in indexes]
        payload[group] = classification_metrics(expected_group, predicted_group)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="评测 AegisGate 打包 ONNX 五分类模型")
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--evidence-threshold", type=float, default=DEFAULT_EVIDENCE_THRESHOLD)
    parser.add_argument(
        "--evaluation-purpose",
        choices=("sealed_baseline", "post_fix_regression"),
        default="post_fix_regression",
        help="标记测试集是否仍为首次封存评测；默认只作修复后回归",
    )
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args()
    if not 0 < args.evidence_threshold <= 1:
        raise ValueError("evidence-threshold 必须位于 (0, 1]")

    data_dir = args.data_dir.resolve()
    manifest_path = (args.manifest or data_dir / "dataset_manifest.json").resolve()
    if manifest_path.parent != data_dir:
        raise ValueError("manifest 必须位于 data-dir 内")
    preliminary = json.loads(manifest_path.read_text(encoding="utf-8"))
    require_v2 = preliminary.get("dataset_version") == "2.0.0"
    manifest, loaded, manifest_sha256 = verify_dataset_manifest(
        manifest_path,
        ("test",),
        require_v2_metadata=require_v2,
    )
    rows = loaded["test"]

    model_dir = args.model_dir.resolve()
    classifier = PretrainedONNXClassifier(model_dir)
    status = classifier.status()
    if status["status"] != "ready":
        print(json.dumps(status, ensure_ascii=False))
        return 2

    expected: list[str] = []
    predicted: list[str] = []
    thresholded: list[str] = []
    details: list[dict[str, Any]] = []
    for row in rows:
        prediction = classifier.predict(str(row["text"]))
        if prediction is None:
            print(json.dumps(classifier.status(), ensure_ascii=False))
            return 2
        expected_label = str(row["label"])
        evidence_label = (
            prediction.label
            if prediction.label != "normal" and prediction.confidence >= args.evidence_threshold
            else "normal"
        )
        expected.append(expected_label)
        predicted.append(prediction.label)
        thresholded.append(evidence_label)
        details.append(
            {
                "id": row.get("id"),
                "variant_type": row.get("variant_type", "legacy_v1"),
                "subtype": row.get("subtype", "legacy_v1"),
                "expected": expected_label,
                "predicted": prediction.label,
                "confidence": round(prediction.confidence, 6),
                "evidence_label": evidence_label,
                "raw_correct": prediction.label == expected_label,
            }
        )

    engine = SafetyEngine(ROOT)
    engine.pretrained_classifier = classifier
    gateway_interventions: list[bool] = []
    gateway_category_hits: Counter[str] = Counter()
    gateway_category_totals: Counter[str] = Counter()
    gateway_actions: Counter[str] = Counter()
    for row, detail in zip(rows, details):
        decision = engine.detect(str(row["text"]), "input")
        intervention = decision.action != "pass"
        gateway_interventions.append(intervention)
        gateway_actions[decision.action] += 1
        expected_label = str(row["label"])
        gateway_category_totals[expected_label] += 1
        category_hit = (
            decision.action == "pass" and not decision.official_categories
            if expected_label == "normal"
            else expected_label in decision.official_categories
        )
        gateway_category_hits[expected_label] += int(category_hit)
        detail["gateway_action"] = decision.action
        detail["gateway_official_categories"] = decision.official_categories
        detail["gateway_risk_score"] = decision.risk_score

    raw_metrics = classification_metrics(expected, predicted)
    thresholded_metrics = classification_metrics(expected, thresholded)
    thresholded_binary = intervention_metrics(
        expected,
        [label != "normal" for label in thresholded],
    )
    gateway_binary = intervention_metrics(expected, gateway_interventions)
    payload = {
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "evaluation_purpose": args.evaluation_purpose,
        "independent_holdout": args.evaluation_purpose == "sealed_baseline",
        "scope_notice": (
            f"仅适用于随附的 {len(rows)} 条项目组自建合成封存测试样本，"
            "不代表开放环境或生产准确率。"
            + (
                "该测试集已被用于问题分析，本次结果仅是修复后回归，不是新的独立盲测。"
                if args.evaluation_purpose == "post_fix_regression"
                else "本次记录为模型冻结后的首次封存评测。"
            )
        ),
        "dataset": {
            "dataset_id": manifest.get("dataset_id", "legacy-v1"),
            "dataset_version": manifest.get("dataset_version", "1.0.0"),
            "manifest_sha256": manifest_sha256,
            "test_file": "test.jsonl",
            "test_data_sha256": manifest["files"]["test.jsonl"]["sha256"],
            "test_samples": len(rows),
        },
        "model": {
            "status": classifier.status(),
            "model_sha256": sha256(model_dir / "model.onnx"),
            "model_bytes": (model_dir / "model.onnx").stat().st_size,
            "execution_provider": "CPUExecutionProvider",
        },
        "gateway_artifacts": {
            "engine_sha256": sha256(ROOT / "src" / "aegisguard" / "engine.py"),
            "policy_sha256": sha256(ROOT / "config" / "safety_policy.json"),
            "keyword_library_sha256": sha256(ROOT / "data" / "keyword_library_v2.json"),
        },
        "raw_classifier": raw_metrics,
        "thresholded_evidence": {
            "threshold": args.evidence_threshold,
            "classification": thresholded_metrics,
            "binary": thresholded_binary,
        },
        "end_to_end_gateway": {
            "binary": gateway_binary,
            "actions": dict(sorted(gateway_actions.items())),
            "official_category_recall": {
                label: round(
                    gateway_category_hits[label] / max(1, gateway_category_totals[label]),
                    6,
                )
                for label in LABELS
            },
        },
        "by_variant_type": grouped_raw_metrics(rows, predicted, "variant_type"),
        "by_subtype": grouped_raw_metrics(rows, predicted, "subtype"),
        "details": details,
    }
    if not args.no_write:
        report = args.report.resolve()
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
