#!/usr/bin/env python3
"""Explicit, low-risk connectivity check for the configured DeepSeek API."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.llm import LLMClient  # noqa: E402


SAFE_SMOKE_TEXT = "请用一句话说明内容安全网关的作用。"
DEEPSEEK_SMOKE_CONFIG = {
    "provider": "deepseek",
    "api_url": "https://api.deepseek.com/chat/completions",
    "model_name": "deepseek-chat",
    "timeout_seconds": 25,
    "api_key_env": "DEEPSEEK_API_KEY",
}


def main() -> int:
    if not os.environ.get("DEEPSEEK_API_KEY", "").strip():
        print("SKIPPED provider=deepseek model=deepseek-chat status=missing_api_key")
        return 2
    with tempfile.TemporaryDirectory(prefix="aegis-deepseek-smoke-") as directory:
        config_path = Path(directory) / "api_config.json"
        config_path.write_text(
            json.dumps(DEEPSEEK_SMOKE_CONFIG, ensure_ascii=False),
            encoding="utf-8",
        )
        result = LLMClient(config_path).chat(SAFE_SMOKE_TEXT)
    if result.status == "ok":
        print(f"SUCCESS provider={result.provider} model={result.model_name} status=ok")
        return 0
    print(f"FAILED provider={result.provider} model={result.model_name} status=unavailable")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
