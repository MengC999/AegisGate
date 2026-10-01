from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from .normalizer import normalize
from .storage import ReloadableJson


def tokenize(text: str) -> list[str]:
    view = normalize(text)
    latin = re.findall(r"[a-z0-9]+", view.canonical)
    chinese = re.findall(r"[\u4e00-\u9fff]", view.canonical)
    bigrams = ["".join(chinese[index:index + 2]) for index in range(len(chinese) - 1)]
    trigrams = ["".join(chinese[index:index + 3]) for index in range(len(chinese) - 2)]
    return latin + (chinese if len(chinese) == 1 else []) + bigrams + trigrams


class NaiveBayesClassifier:
    def __init__(self, model_path: Path) -> None:
        self._model = ReloadableJson(model_path, {})

    def predict(self, text: str) -> tuple[str, float]:
        model: dict[str, Any] = self._model.get()
        labels = model.get("labels", [])
        vocab = model.get("vocab", [])
        label_counts = model.get("label_counts", {})
        if not labels or not vocab:
            return "normal", 0.0
        tokens = tokenize(text)
        if not tokens:
            return "normal", 1.0

        total_docs = max(1, sum(label_counts.values()))
        vocab_size = max(1, len(vocab))
        scores: dict[str, float] = {}
        for label in labels:
            prior = (label_counts.get(label, 0) + 1) / (total_docs + len(labels))
            score = math.log(prior)
            counts = model.get("token_counts", {}).get(label, {})
            denominator = model.get("total_tokens", {}).get(label, 0) + vocab_size
            for token in tokens:
                score += math.log((counts.get(token, 0) + 1) / denominator)
            scores[label] = score

        peak = max(scores.values())
        probabilities = {label: math.exp(score - peak) for label, score in scores.items()}
        denominator = sum(probabilities.values()) or 1.0
        probabilities = {label: value / denominator for label, value in probabilities.items()}
        label = max(probabilities, key=probabilities.get)
        return label, probabilities[label]
