from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


LABELS = ["normal", "sexual", "violence", "advertising", "sensitive_speech"]
V2_REQUIRED_FIELDS = {
    "id",
    "split",
    "label",
    "text",
    "subtype",
    "variant_type",
    "family_id",
    "source_batch",
    "source_type",
    "source",
    "license",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(
    path: Path,
    expected_split: str | None = None,
    require_v2_metadata: bool = False,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"{path.name}:{line_number} 数据格式错误")
        if row.get("label") not in LABELS or not isinstance(row.get("text"), str):
            raise ValueError(f"{path.name}:{line_number} 数据格式错误")
        if expected_split is not None and row.get("split") != expected_split:
            raise ValueError(f"{path.name}:{line_number} split 不匹配")
        if require_v2_metadata and not V2_REQUIRED_FIELDS.issubset(row):
            missing = sorted(V2_REQUIRED_FIELDS - set(row))
            raise ValueError(f"{path.name}:{line_number} 缺少 v2 字段: {missing}")
        rows.append(row)
    return rows


def verify_dataset_manifest(
    manifest_path: Path,
    splits: tuple[str, ...],
    require_v2_metadata: bool = False,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]], str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("labels") != LABELS:
        raise ValueError("数据 manifest 标签或格式无效")
    data_dir = manifest_path.parent
    file_metadata = manifest.get("files")
    if not isinstance(file_metadata, dict):
        raise ValueError("数据 manifest 缺少 files")
    loaded: dict[str, list[dict[str, Any]]] = {}
    for split in splits:
        name = f"{split}.jsonl"
        metadata = file_metadata.get(name)
        if not isinstance(metadata, dict):
            raise ValueError(f"数据 manifest 缺少 {name}")
        path = data_dir / name
        expected_hash = metadata.get("sha256")
        if not path.is_file() or not isinstance(expected_hash, str) or sha256(path) != expected_hash:
            raise ValueError(f"数据文件 SHA-256 校验失败: {name}")
        rows = load_jsonl(path, split, require_v2_metadata)
        if len(rows) != metadata.get("rows"):
            raise ValueError(f"数据行数与 manifest 不匹配: {name}")
        expected_labels = metadata.get("labels")
        actual_labels = {
            label: sum(row["label"] == label for row in rows)
            for label in LABELS
        }
        if actual_labels != expected_labels:
            raise ValueError(f"标签计数与 manifest 不匹配: {name}")
        loaded[split] = rows
    return manifest, loaded, sha256(manifest_path)


def verify_group_isolation(rows_by_split: dict[str, list[dict[str, Any]]]) -> None:
    family_splits: dict[str, set[str]] = {}
    batch_splits: dict[str, set[str]] = {}
    ids: set[str] = set()
    for split, rows in rows_by_split.items():
        for row in rows:
            row_id = str(row.get("id", ""))
            if not row_id or row_id in ids:
                raise ValueError(f"数据 ID 缺失或重复: {row_id}")
            ids.add(row_id)
            family_splits.setdefault(str(row.get("family_id", "")), set()).add(split)
            batch_splits.setdefault(str(row.get("source_batch", "")), set()).add(split)
    if any(not family or len(splits) != 1 for family, splits in family_splits.items()):
        raise ValueError("family_id 存在跨切分泄漏")
    if any(not batch or len(splits) != 1 for batch, splits in batch_splits.items()):
        raise ValueError("source_batch 存在跨切分泄漏")


def classification_metrics(expected: list[str], predicted: list[str]) -> dict[str, Any]:
    if len(expected) != len(predicted) or not expected:
        raise ValueError("评测标签长度不匹配或为空")
    matrix = [[0 for _ in LABELS] for _ in LABELS]
    for truth, prediction in zip(expected, predicted):
        matrix[LABELS.index(truth)][LABELS.index(prediction)] += 1

    per_class: dict[str, dict[str, float | int]] = {}
    for index, label in enumerate(LABELS):
        true_positive = matrix[index][index]
        false_positive = sum(matrix[row][index] for row in range(len(LABELS)) if row != index)
        false_negative = sum(matrix[index][column] for column in range(len(LABELS)) if column != index)
        support = sum(matrix[index])
        precision = true_positive / max(1, true_positive + false_positive)
        recall = true_positive / max(1, true_positive + false_negative)
        f1 = 2 * precision * recall / max(1e-12, precision + recall)
        per_class[label] = {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "support": support,
        }

    correct = sum(matrix[index][index] for index in range(len(LABELS)))
    true_violations = sum(label != "normal" for label in expected)
    intercepted_violations = sum(
        truth != "normal" and prediction != "normal"
        for truth, prediction in zip(expected, predicted)
    )
    normal_total = sum(label == "normal" for label in expected)
    normal_false_positives = sum(
        truth == "normal" and prediction != "normal"
        for truth, prediction in zip(expected, predicted)
    )
    predicted_interventions = sum(label != "normal" for label in predicted)
    return {
        "samples": len(expected),
        "accuracy": round(correct / len(expected), 6),
        "macro_f1": round(sum(float(item["f1"]) for item in per_class.values()) / len(LABELS), 6),
        "per_class": per_class,
        "confusion_matrix": {"labels": LABELS, "rows_actual_columns_predicted": matrix},
        "overall_intervention_rate": round(predicted_interventions / len(expected), 6),
        "violation_interception_rate": round(intercepted_violations / max(1, true_violations), 6),
        "normal_false_positive_rate": round(normal_false_positives / max(1, normal_total), 6),
    }
