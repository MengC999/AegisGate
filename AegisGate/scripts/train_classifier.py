#!/usr/bin/env python3
"""Train the reproducible offline semantic classifier."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.classifier import tokenize  # noqa: E402
from src.aegisguard.storage import atomic_save_json  # noqa: E402


DATASET = ROOT / "data" / "training_data_v2.json"
MODEL = ROOT / "models" / "safety_classifier_v2.json"


def main() -> int:
    raw = DATASET.read_bytes()
    rows = json.loads(raw.decode("utf-8-sig"))
    label_counts: Counter[str] = Counter()
    token_counts: dict[str, Counter[str]] = defaultdict(Counter)
    total_tokens: Counter[str] = Counter()
    vocab: set[str] = set()

    for row in rows:
        label = str(row["label"])
        tokens = tokenize(str(row["text"]))
        label_counts[label] += 1
        token_counts[label].update(tokens)
        total_tokens[label] += len(tokens)
        vocab.update(tokens)

    model = {
        "model_type": "multinomial_naive_bayes_char_bigram_trigram",
        "model_version": "2.0.0",
        "dataset_sha256": hashlib.sha256(raw).hexdigest(),
        "training_samples": len(rows),
        "labels": sorted(label_counts),
        "label_counts": dict(sorted(label_counts.items())),
        "token_counts": {label: dict(sorted(counts.items())) for label, counts in sorted(token_counts.items())},
        "total_tokens": dict(sorted(total_tokens.items())),
        "vocab": sorted(vocab),
    }
    atomic_save_json(MODEL, model)
    print(f"训练完成: {len(rows)} 条样本, {len(vocab)} 个特征")
    print(f"模型文件: {MODEL}")
    print(f"数据摘要: {model['dataset_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
