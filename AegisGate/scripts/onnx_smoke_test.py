#!/usr/bin/env python3
"""Load the packaged ONNX with CPUExecutionProvider and perform real inference."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.onnx_classifier import PretrainedONNXClassifier  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="AegisGate 本地 ONNX CPU 推理验收")
    parser.add_argument("--text", default="请帮我整理一份会议纪要。")
    args = parser.parse_args()
    classifier = PretrainedONNXClassifier(ROOT / "models" / "official_four_onnx_v2")
    status = classifier.status()
    if status["status"] != "ready":
        print(json.dumps(status, ensure_ascii=False))
        return 2
    prediction = classifier.predict(args.text)
    if prediction is None:
        print(json.dumps(classifier.status(), ensure_ascii=False))
        return 2
    print(
        json.dumps(
            {
                "status": "success",
                "backend": "onnxruntime-cpu",
                "label": prediction.label,
                "confidence": round(prediction.confidence, 6),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
