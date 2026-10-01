from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXPECTED_LABELS = ["normal", "sexual", "violence", "advertising", "sensitive_speech"]
# Keep the expected package identity visible even when the package is absent;
# status/reason remain the authoritative unavailable/invalid signal.
DEFAULT_MODEL_ID = "aegisgate-official-four-rbt3-v2"


@dataclass(frozen=True)
class PretrainedPrediction:
    label: str
    confidence: float
    probabilities: dict[str, float]


class BertWordPieceTokenizer:
    def __init__(self, vocab_path: Path, max_length: int = 96, do_lower_case: bool = True) -> None:
        tokens = [line.removesuffix("\r") for line in vocab_path.read_text(encoding="utf-8").split("\n")]
        if tokens and tokens[-1] == "":
            tokens.pop()
        self.vocab = {token: index for index, token in enumerate(tokens)}
        self.max_length = max_length
        self.do_lower_case = do_lower_case
        for required in ("[PAD]", "[UNK]", "[CLS]", "[SEP]"):
            if required not in self.vocab:
                raise ValueError(f"词表缺少 {required}")

    def encode(self, text: str) -> tuple[list[int], list[int], list[int]]:
        wordpieces: list[str] = []
        for token in self._basic_tokens(text):
            wordpieces.extend(self._wordpiece(token))
        tokens = ["[CLS]", *wordpieces[: self.max_length - 2], "[SEP]"]
        input_ids = [self.vocab.get(token, self.vocab["[UNK]"]) for token in tokens]
        attention_mask = [1] * len(input_ids)
        token_type_ids = [0] * len(input_ids)
        padding = self.max_length - len(input_ids)
        input_ids.extend([self.vocab["[PAD]"]] * padding)
        attention_mask.extend([0] * padding)
        token_type_ids.extend([0] * padding)
        return input_ids, attention_mask, token_type_ids

    def _basic_tokens(self, text: str) -> list[str]:
        cleaned: list[str] = []
        for char in unicodedata.normalize("NFC", text):
            code = ord(char)
            category = unicodedata.category(char)
            if code in {0, 0xFFFD} or category in {"Cc", "Cf"}:
                continue
            if char.isspace():
                cleaned.append(" ")
            elif self._is_cjk(char) or self._is_punctuation(char):
                cleaned.extend((" ", char, " "))
            else:
                cleaned.append(char)
        output: list[str] = []
        for token in "".join(cleaned).strip().split():
            if self.do_lower_case:
                token = "".join(
                    char
                    for char in unicodedata.normalize("NFD", token.lower())
                    if unicodedata.category(char) != "Mn"
                )
            if token:
                output.append(token)
        return output

    def _wordpiece(self, token: str) -> list[str]:
        if len(token) > 100:
            return ["[UNK]"]
        pieces: list[str] = []
        start = 0
        while start < len(token):
            end = len(token)
            current = ""
            while start < end:
                candidate = token[start:end]
                if start:
                    candidate = "##" + candidate
                if candidate in self.vocab:
                    current = candidate
                    break
                end -= 1
            if not current:
                return ["[UNK]"]
            pieces.append(current)
            start = end
        return pieces

    @staticmethod
    def _is_cjk(char: str) -> bool:
        code = ord(char)
        return (
            0x4E00 <= code <= 0x9FFF
            or 0x3400 <= code <= 0x4DBF
            or 0x20000 <= code <= 0x2A6DF
            or 0x2A700 <= code <= 0x2B73F
            or 0x2B740 <= code <= 0x2B81F
            or 0x2B820 <= code <= 0x2CEAF
            or 0xF900 <= code <= 0xFAFF
        )

    @staticmethod
    def _is_punctuation(char: str) -> bool:
        code = ord(char)
        return 33 <= code <= 47 or 58 <= code <= 64 or 91 <= code <= 96 or 123 <= code <= 126 or unicodedata.category(char).startswith("P")


class PretrainedONNXClassifier:
    def __init__(self, model_dir: Path) -> None:
        self.model_dir = model_dir
        self._numpy: Any = None
        self._session: Any = None
        self._tokenizer: BertWordPieceTokenizer | None = None
        self._labels: list[str] = []
        self._model_id = DEFAULT_MODEL_ID
        self._status = "unavailable"
        self._reason = "not_loaded"
        self._load()

    def status(self) -> dict[str, str]:
        return {
            "model_id": self._model_id,
            "status": self._status,
            "reason": self._reason,
            "backend": "onnxruntime-cpu",
        }

    def predict(self, text: str) -> PretrainedPrediction | None:
        if (
            self._status != "ready"
            or self._numpy is None
            or self._session is None
            or self._tokenizer is None
        ):
            return None
        try:
            input_ids, attention_mask, token_type_ids = self._tokenizer.encode(text)
            inputs = {
                "input_ids": self._numpy.asarray([input_ids], dtype=self._numpy.int64),
                "attention_mask": self._numpy.asarray([attention_mask], dtype=self._numpy.int64),
                "token_type_ids": self._numpy.asarray([token_type_ids], dtype=self._numpy.int64),
            }
            logits = self._session.run(["logits"], inputs)[0][0]
            values = [float(value) for value in logits]
            peak = max(values)
            exponentials = [math.exp(value - peak) for value in values]
            denominator = sum(exponentials) or 1.0
            probabilities = [value / denominator for value in exponentials]
            index = max(range(len(probabilities)), key=probabilities.__getitem__)
            return PretrainedPrediction(
                label=self._labels[index],
                confidence=probabilities[index],
                probabilities=dict(zip(self._labels, probabilities)),
            )
        except Exception:
            self._status = "invalid"
            self._reason = "inference_failed"
            return None

    def _load(self) -> None:
        required = {
            "model.onnx",
            "vocab.txt",
            "labels.json",
            "tokenizer_config.json",
            "model_card.md",
            "SOURCE.json",
            "LICENSE.apache-2.0.txt",
            "SHA256SUMS",
        }
        missing = sorted(name for name in required if not (self.model_dir / name).is_file())
        if missing:
            self._status = "unavailable"
            self._reason = "missing_files"
            return
        if not self._verify_hashes():
            self._status = "invalid"
            self._reason = "checksum_mismatch"
            return
        try:
            source_payload = json.loads((self.model_dir / "SOURCE.json").read_text(encoding="utf-8"))
            model_id = source_payload.get("model_id", DEFAULT_MODEL_ID)
            if not isinstance(model_id, str) or not model_id.startswith("aegisgate-official-four-rbt3-v"):
                raise ValueError("模型 ID 无效")
            self._model_id = model_id
            labels_payload = json.loads((self.model_dir / "labels.json").read_text(encoding="utf-8"))
            labels = labels_payload.get("labels", [])
            if labels != EXPECTED_LABELS:
                raise ValueError("标签顺序不匹配")
            tokenizer_config = json.loads((self.model_dir / "tokenizer_config.json").read_text(encoding="utf-8"))
            self._tokenizer = BertWordPieceTokenizer(
                self.model_dir / "vocab.txt",
                max_length=int(tokenizer_config.get("max_length", 96)),
                do_lower_case=bool(tokenizer_config.get("do_lower_case", True)),
            )
            try:
                import numpy as np
            except ImportError:
                self._status = "unavailable"
                self._reason = "numpy_missing"
                self._tokenizer = None
                return
            try:
                import onnxruntime as ort
            except ImportError:
                self._status = "unavailable"
                self._reason = "onnxruntime_missing"
                self._tokenizer = None
                return

            self._session = ort.InferenceSession(
                str(self.model_dir / "model.onnx"),
                providers=["CPUExecutionProvider"],
            )
            input_names = {item.name for item in self._session.get_inputs()}
            if input_names != {"input_ids", "attention_mask", "token_type_ids"}:
                raise ValueError("ONNX 输入不匹配")
            if "logits" not in {item.name for item in self._session.get_outputs()}:
                raise ValueError("ONNX 输出不匹配")
            self._numpy = np
            self._labels = labels
            self._status = "ready"
            self._reason = "verified"
        except Exception:
            self._status = "invalid"
            self._reason = "load_failed"
            self._numpy = None
            self._session = None
            self._tokenizer = None

    def _verify_hashes(self) -> bool:
        try:
            lines = (self.model_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            if not lines:
                return False
            for line in lines:
                digest, relative = line.split("  ", 1)
                if len(digest) != 64 or Path(relative).name != relative:
                    return False
                path = self.model_dir / relative
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    return False
            return True
        except (OSError, ValueError):
            return False
