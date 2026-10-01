#!/usr/bin/env python3
"""Run an explicit local-only generation through AegisGate's safety pipeline."""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.service import ConversationService  # noqa: E402


def main() -> int:
    config_path = ROOT / "config/deepseek_local.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    endpoint = urlparse(config["api_url"])
    if endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1":
        print("FAILED: this smoke test only permits the local inference endpoint")
        return 2
    with tempfile.TemporaryDirectory(prefix="aegis-local-model-smoke-") as directory:
        service = ConversationService(ROOT, runtime_dir=Path(directory), model_config_path=config_path)
        started = time.perf_counter()
        try:
            result = service.process("只回复数字 5。不要输出其他内容。")
            print(json.dumps({
                "provider": result.model_provider,
                "model": result.model_name,
                "status": result.model_status,
                "action": result.action,
                "model_called": result.model_called,
                "seconds": round(time.perf_counter() - started, 2),
                "safe_output": result.final_output,
            }, ensure_ascii=False))
            return 0 if result.model_status == "ok" and result.model_called and result.action == "pass" and result.final_output.strip() == "5" else 1
        finally:
            service.close()


if __name__ == "__main__":
    raise SystemExit(main())
