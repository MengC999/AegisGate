#!/usr/bin/env python3
"""Export a text-free decision trace for normal samples that were intercepted.

The source dataset is read only for evaluation.  The diagnostic deliberately
omits raw text and Evidence.matched values so the artifact is safe to share.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aegisguard.engine import SafetyEngine  # noqa: E402
from scripts.semantic_model_common import sha256  # noqa: E402


DEFAULT_DATASET = ROOT / "data" / "semantic_classifier_v2" / "test.jsonl"
DEFAULT_JSON = ROOT / "reports" / "semantic_gateway_false_positive_diagnostics.json"
DEFAULT_CSV = ROOT / "reports" / "semantic_gateway_false_positive_diagnostics.csv"


def _load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"数据行 {line_number} 不是对象")
        if not isinstance(row.get("id"), str) or not isinstance(row.get("label"), str):
            raise ValueError(f"数据行 {line_number} 缺少 id 或 label")
        if not isinstance(row.get("text"), str):
            raise ValueError(f"数据行 {line_number} 缺少 text")
        rows.append(row)
    if not rows:
        raise ValueError("数据集为空")
    return rows


def _evidence_summary(decision: Any) -> list[dict[str, Any]]:
    return [
        {
            "rule_id": item.rule_id,
            "source": item.source,
            "category": item.category,
            "official_category": (
                decision.official_categories[0]
                if item.category in decision.categories and len(decision.official_categories) == 1
                else None
            ),
            "score": round(float(item.score), 6),
        }
        for item in decision.evidence
    ]


def build_diagnostic(
    rows: Iterable[dict[str, Any]],
    engine: SafetyEngine,
    *,
    direction: str | None = None,
) -> dict[str, Any]:
    rows = list(rows)
    normal_rows = [row for row in rows if row.get("label") == "normal"]
    false_positives: list[dict[str, Any]] = []
    action_counts: Counter[str] = Counter()
    for row in normal_rows:
        row_direction = str(row.get("direction") or direction or "input")
        if row_direction not in {"input", "output"}:
            raise ValueError(f"不支持的方向: {row_direction}")
        decision = engine.detect(str(row["text"]), row_direction)
        action_counts[decision.action] += 1
        if decision.action == "pass":
            continue
        source_scores = decision.explanation.get("source_scores", {})
        category_scores = decision.explanation.get("category_scores", {})
        false_positives.append(
            {
                "sample_id": row["id"],
                "expected_label": "normal",
                "variant_type": row.get("variant_type", "unspecified"),
                "subtype": row.get("subtype", "unspecified"),
                "direction": row_direction,
                "history_included": bool(row.get("history")),
                "actual_action": decision.action,
                "risk_level": decision.risk_level,
                "risk_score": decision.risk_score,
                "official_categories": decision.official_categories,
                "internal_categories": decision.categories,
                "context_flags": decision.context_flags,
                "evidence": _evidence_summary(decision),
                "source_scores": source_scores,
                "category_scores": category_scores,
                "thresholds": {
                    "pass": engine.policy.threshold("pass", 0.35),
                    "block": engine.policy.threshold("block", 0.82),
                },
                "context_adjustments": decision.explanation.get("context_adjustments", []),
                "fusion": {
                    "raw_risk_score": decision.explanation.get("raw_risk_score"),
                    "calibrated_risk_score": decision.explanation.get("calibrated_risk_score"),
                },
                "evidence_scope": "input" if row_direction == "input" else "output",
            }
        )

    denominator = len(normal_rows)
    return {
        "diagnostic_version": "1.0.0",
        "purpose": "post_fix_false_positive_diagnosis",
        "privacy_notice": "仅保留样本 ID 与决策摘要；不含原始文本、匹配片段、认证头或密钥。",
        "dataset": {
            "samples": len(rows),
            "normal_samples": denominator,
            "normal_false_positive_samples": len(false_positives),
            "normal_false_positive_rate": round(len(false_positives) / max(1, denominator), 6),
        },
        "direction_scope": sorted({
            str(row.get("direction") or direction or "input") for row in rows
        }),
        "model_status": engine.semantic_model_status(),
        "action_counts_on_normal": dict(sorted(action_counts.items())),
        "false_positives": false_positives,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "sample_id", "expected_label", "variant_type", "subtype", "direction",
        "history_included", "actual_action", "risk_level", "risk_score",
        "official_categories", "internal_categories", "context_flags", "evidence",
        "source_scores", "category_scores", "thresholds", "context_adjustments", "fusion",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                field: json.dumps(row[field], ensure_ascii=False, sort_keys=True)
                if isinstance(row[field], (list, dict))
                else row[field]
                for field in fields
            })


def main() -> int:
    parser = argparse.ArgumentParser(description="导出正常文本误判的无文本决策诊断")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--csv-output", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--direction", choices=("input", "output"))
    args = parser.parse_args()

    dataset = args.dataset.resolve()
    rows = _load_rows(dataset)
    engine = SafetyEngine(ROOT)
    report = build_diagnostic(rows, engine, direction=args.direction)
    report["dataset"]["file"] = dataset.name
    report["dataset"]["sha256"] = sha256(dataset)
    json_output = args.json_output.resolve()
    json_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    write_csv(args.csv_output.resolve(), report["false_positives"])
    print(json.dumps({
        "normal_samples": report["dataset"]["normal_samples"],
        "false_positive_samples": report["dataset"]["normal_false_positive_samples"],
        "normal_false_positive_rate": report["dataset"]["normal_false_positive_rate"],
        "json_output": str(json_output),
        "csv_output": str(args.csv_output.resolve()),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
