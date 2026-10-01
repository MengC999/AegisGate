#!/usr/bin/env python3
"""Explicitly fine-tune the pinned rbt3 encoder and export a real ONNX classifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.semantic_model_common import (  # noqa: E402
    LABELS,
    classification_metrics,
    verify_dataset_manifest,
)


BASE_MODEL = "hfl/rbt3"
BASE_REVISION = "0aa0527ff4170f29e1dfd3eb6ef60dc67e1bf75c"
BASE_URL = "https://huggingface.co/hfl/rbt3"
LICENSE_URL = "https://github.com/ymcui/Chinese-BERT-wwm/blob/master/LICENSE"
DEFAULT_DATA_DIR = ROOT / "data" / "semantic_classifier_v2"
DEFAULT_OUTPUT_DIR = ROOT / "models" / "official_four_onnx_v2"
LICENSE_SOURCE = ROOT / "models" / "licenses" / "Apache-2.0.txt"
SEED = 20260818


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="微调 hfl/rbt3 并导出 AegisGate 五分类 ONNX")
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--max-length", type=int, default=96)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    if args.epochs < 1 or args.batch_size < 1 or not 0 < args.learning_rate < 1:
        raise ValueError("训练参数无效")
    if not LICENSE_SOURCE.is_file():
        raise FileNotFoundError("缺少上游 Apache-2.0 许可证文本")
    data_dir = args.data_dir.resolve()
    manifest_path = (args.manifest or data_dir / "dataset_manifest.json").resolve()
    if manifest_path.parent != data_dir:
        raise ValueError("manifest 必须位于 data-dir 内")
    manifest, split_rows, manifest_sha256 = verify_dataset_manifest(
        manifest_path,
        ("train", "validation"),
        require_v2_metadata=True,
    )
    if manifest.get("dataset_version") != "2.0.0":
        raise ValueError("训练入口只接受已封存的 v2 数据")
    output_dir = args.output_dir.resolve()
    staging_dir = output_dir.with_name(output_dir.name + ".staging")
    if output_dir.exists() or staging_dir.exists():
        raise FileExistsError("输出目录或 staging 已存在；禁止覆盖已有模型")

    try:
        import torch
        from huggingface_hub import hf_hub_download
        from torch.utils.data import DataLoader, Dataset
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        print("缺少训练依赖，请先安装 requirements-training.txt。")
        print(f"缺失模块: {exc.name}")
        return 2

    random.seed(SEED)
    torch.manual_seed(SEED)
    torch.use_deterministic_algorithms(True, warn_only=True)
    torch.set_num_threads(max(1, min(8, torch.get_num_threads())))
    label_to_id = {label: index for index, label in enumerate(LABELS)}
    train_rows = split_rows["train"]
    validation_rows = split_rows["validation"]

    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL,
        revision=BASE_REVISION,
        use_fast=False,
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        revision=BASE_REVISION,
        num_labels=len(LABELS),
        id2label={index: label for index, label in enumerate(LABELS)},
        label2id=label_to_id,
        ignore_mismatched_sizes=True,
    )
    model.to("cpu")

    class TextDataset(Dataset):
        def __init__(self, rows: list[dict[str, Any]]) -> None:
            self.rows = rows
            self.encoded = tokenizer(
                [str(row["text"]) for row in rows],
                padding="max_length",
                truncation=True,
                max_length=args.max_length,
                return_tensors="pt",
            )

        def __len__(self) -> int:
            return len(self.rows)

        def __getitem__(self, index: int) -> dict[str, Any]:
            return {
                "input_ids": self.encoded["input_ids"][index],
                "attention_mask": self.encoded["attention_mask"][index],
                "token_type_ids": self.encoded["token_type_ids"][index],
                "labels": torch.tensor(label_to_id[str(self.rows[index]["label"])], dtype=torch.long),
            }

    generator = torch.Generator().manual_seed(SEED)
    train_loader = DataLoader(
        TextDataset(train_rows),
        batch_size=args.batch_size,
        shuffle=True,
        generator=generator,
    )
    validation_loader = DataLoader(TextDataset(validation_rows), batch_size=args.batch_size)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)

    def evaluate() -> tuple[dict[str, Any], list[str]]:
        model.eval()
        expected: list[str] = []
        predicted: list[str] = []
        with torch.no_grad():
            for batch in validation_loader:
                labels = batch.pop("labels")
                logits = model(**batch).logits
                expected.extend(LABELS[index] for index in labels.tolist())
                predicted.extend(LABELS[index] for index in logits.argmax(dim=-1).tolist())
        return classification_metrics(expected, predicted), predicted

    best_state: dict[str, Any] | None = None
    best_metrics: dict[str, Any] | None = None
    history: list[dict[str, Any]] = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        losses: list[float] = []
        for batch in train_loader:
            optimizer.zero_grad(set_to_none=True)
            loss = model(**batch).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            losses.append(float(loss.detach()))
        metrics, _ = evaluate()
        epoch_result = {
            "epoch": epoch,
            "train_loss": round(sum(losses) / max(1, len(losses)), 6),
            "validation_accuracy": metrics["accuracy"],
            "validation_macro_f1": metrics["macro_f1"],
            "validation_sensitive_speech_recall": metrics["per_class"]["sensitive_speech"]["recall"],
        }
        history.append(epoch_result)
        print(json.dumps(epoch_result, ensure_ascii=False))
        selection_score = (
            float(metrics["macro_f1"]),
            float(metrics["per_class"]["sensitive_speech"]["recall"]),
        )
        best_score = (
            (
                float(best_metrics["macro_f1"]),
                float(best_metrics["per_class"]["sensitive_speech"]["recall"]),
            )
            if best_metrics is not None
            else (-1.0, -1.0)
        )
        if selection_score > best_score:
            best_metrics = metrics
            best_state = deepcopy(model.state_dict())

    if best_state is None or best_metrics is None:
        raise RuntimeError("训练未产生模型")
    model.load_state_dict(best_state)
    model.eval()
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir.mkdir()

    class LogitsOnly(torch.nn.Module):
        def __init__(self, classifier: Any) -> None:
            super().__init__()
            self.classifier = classifier

        def forward(self, input_ids: Any, attention_mask: Any, token_type_ids: Any) -> Any:
            return self.classifier(
                input_ids=input_ids,
                attention_mask=attention_mask,
                token_type_ids=token_type_ids,
            ).logits

    sample = tokenizer(
        "请帮我整理会议纪要。",
        padding="max_length",
        truncation=True,
        max_length=args.max_length,
        return_tensors="pt",
    )
    onnx_path = staging_dir / "model.onnx"
    torch.onnx.export(
        LogitsOnly(model),
        (sample["input_ids"], sample["attention_mask"], sample["token_type_ids"]),
        str(onnx_path),
        input_names=["input_ids", "attention_mask", "token_type_ids"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "token_type_ids": {0: "batch", 1: "sequence"},
            "logits": {0: "batch"},
        },
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )

    import onnx
    import onnxruntime as ort

    onnx.checker.check_model(onnx.load(str(onnx_path)))
    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    if "logits" not in {item.name for item in session.get_outputs()}:
        raise RuntimeError("导出 ONNX 缺少 logits 输出")

    vocab_source = Path(hf_hub_download(BASE_MODEL, "vocab.txt", revision=BASE_REVISION))
    weight_source = Path(hf_hub_download(BASE_MODEL, "pytorch_model.bin", revision=BASE_REVISION))
    shutil.copyfile(vocab_source, staging_dir / "vocab.txt")
    shutil.copyfile(LICENSE_SOURCE, staging_dir / "LICENSE.apache-2.0.txt")
    (staging_dir / "tokenizer_config.json").write_text(
        json.dumps(
            {
                "type": "bert_wordpiece",
                "do_lower_case": bool(getattr(tokenizer, "do_lower_case", True)),
                "max_length": args.max_length,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    labels_payload = {
        "labels": LABELS,
        "official_mapping": {
            "normal": {"official_category": "正常", "engine_category": None},
            "sexual": {"official_category": "色情", "engine_category": "sexual"},
            "violence": {"official_category": "暴力", "engine_category": "violence"},
            "advertising": {"official_category": "广告", "engine_category": "fraud"},
            "sensitive_speech": {"official_category": "敏感话术", "engine_category": "sensitive_speech"},
        },
        "sensitive_speech_definition": "提示注入、隐私泄露、违法实施、仇恨歧视、自伤诱导和有害虚假信息等需要拦截或复核的话术。",
    }
    (staging_dir / "labels.json").write_text(
        json.dumps(labels_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    source_payload = {
        "model_id": "aegisgate-official-four-rbt3-v2",
        "base_model": BASE_MODEL,
        "source_url": BASE_URL,
        "revision": BASE_REVISION,
        "upstream_weight_file": "pytorch_model.bin",
        "upstream_weight_bytes": weight_source.stat().st_size,
        "upstream_weight_sha256": sha256(weight_source),
        "upstream_license": "Apache-2.0",
        "license_evidence": [
            "Hugging Face model card metadata: license=apache-2.0",
            LICENSE_URL,
        ],
        "redistribution": "Fine-tuned derivative; license, attribution, source revision and modification notice are included.",
    }
    (staging_dir / "SOURCE.json").write_text(
        json.dumps(source_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    training_summary = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_id": manifest["dataset_id"],
        "dataset_version": manifest["dataset_version"],
        "dataset_manifest_sha256": manifest_sha256,
        "train_sha256": manifest["files"]["train.jsonl"]["sha256"],
        "validation_sha256": manifest["files"]["validation.jsonl"]["sha256"],
        "seed": SEED,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "max_length": args.max_length,
        "train_rows": len(train_rows),
        "validation_rows": len(validation_rows),
        "test_rows_used_during_training": 0,
        "best_validation_metrics": best_metrics,
        "history": history,
    }
    (staging_dir / "training_summary.json").write_text(
        json.dumps(training_summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    model_card = f"""# AegisGate Official Four rbt3 ONNX v2

- Base encoder: `{BASE_MODEL}` at `{BASE_REVISION}`
- License: Apache-2.0; this directory contains the license and modification notice
- Task labels: `{', '.join(LABELS)}`
- Training data: `{manifest['dataset_id']}` `{manifest['dataset_version']}`; train {len(train_rows)}, validation {len(validation_rows)}
- Dataset manifest SHA-256: `{manifest_sha256}`
- Test-set usage during training: 0
- Runtime: ONNX Runtime CPU; no Torch or Transformers required
- Export: genuine fine-tuned encoder plus five-class linear head, ONNX opset 17
- Best validation accuracy: {best_metrics['accuracy']}
- Best validation macro F1: {best_metrics['macro_f1']}

This model is an AegisGate fine-tuned derivative of HFL rbt3. It is not a rule or constant-output model. Final test-set metrics are produced separately by `python scripts/evaluate_onnx_classifier.py`; validation metrics must not be represented as open-world production accuracy.
"""
    (staging_dir / "model_card.md").write_text(model_card, encoding="utf-8")

    artifact_names = [
        "model.onnx",
        "vocab.txt",
        "labels.json",
        "tokenizer_config.json",
        "model_card.md",
        "SOURCE.json",
        "LICENSE.apache-2.0.txt",
        "training_summary.json",
    ]
    lines = [f"{sha256(staging_dir / name)}  {name}" for name in artifact_names]
    (staging_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    staging_dir.replace(output_dir)
    final_onnx_path = output_dir / "model.onnx"
    print(f"ONNX 导出完成: {final_onnx_path} ({final_onnx_path.stat().st_size} bytes)")
    print(f"ONNX SHA-256: {sha256(final_onnx_path)}")
    print(json.dumps(best_metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
