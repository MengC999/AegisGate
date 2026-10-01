from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

from .storage import ReloadableJson


API_KEY_ENV_NAME = "DEEPSEEK_API_KEY"
DEFAULT_CONFIG = {
    "provider": "mock",
    "api_url": "https://api.deepseek.com/chat/completions",
    "model_name": "deepseek-chat",
    "timeout_seconds": 25,
    "api_key_env": API_KEY_ENV_NAME,
}
MOCK_MODEL_NAME = "aegis-offline-mock"
MOCK_RESPONSE = "已收到你的请求。以下为离线演示模型生成的合规回复：请明确目标、使用边界和预期输出。"
UNAVAILABLE_RESPONSE = "模型服务当前不可用，本次请求未切换到离线 Mock。请稍后重试。"
SUPPORTED_PROVIDERS = {"mock", "deepseek", "openai_compatible"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class LLMResult:
    content: str
    provider: str
    model_name: str
    status: str
    request_sent: bool


class LLMClient:
    """One small client for offline mock, DeepSeek, and OpenAI-compatible APIs."""

    def __init__(self, config_path: Path) -> None:
        self._config = ReloadableJson(config_path, DEFAULT_CONFIG)

    def status(self) -> dict[str, str]:
        settings = self._settings()
        if settings is None:
            return {"provider": "unavailable", "model_name": "", "status": "unavailable"}
        provider = settings["provider"]
        if provider == "mock":
            return {"provider": "mock", "model_name": MOCK_MODEL_NAME, "status": "ready"}
        if not self._real_settings_valid(settings):
            return {
                "provider": provider,
                "model_name": settings["model_name"],
                "status": "unavailable",
            }
        if provider == "deepseek" and not self._api_key():
            return {
                "provider": "deepseek",
                "model_name": settings["model_name"],
                "status": "unavailable",
            }
        return {
            "provider": provider,
            "model_name": settings["model_name"],
            "status": "configured",
        }

    def is_mock_provider(self) -> bool:
        return self.status()["provider"] == "mock"

    def chat(self, safe_input: str, safe_history: Sequence[str] | None = None) -> LLMResult:
        settings = self._settings()
        if settings is None:
            return self._unavailable("unavailable", "", request_sent=False)
        provider = settings["provider"]
        if provider == "mock":
            return LLMResult(MOCK_RESPONSE, "mock", MOCK_MODEL_NAME, "ok", True)
        if not self._real_settings_valid(settings):
            return self._unavailable(provider, settings["model_name"], request_sent=False)

        api_key = self._api_key()
        if provider == "deepseek" and not api_key:
            return self._unavailable("deepseek", settings["model_name"], request_sent=False)

        messages = [{"role": "system", "content": "你是一个遵守中国法律法规与平台安全规范的中文助手。"}]
        for item in (safe_history or [])[-12:]:
            if isinstance(item, str):
                messages.append({"role": "user", "content": item})
        messages.append({"role": "user", "content": safe_input})
        body = json.dumps(
            {"model": settings["model_name"], "messages": messages, "stream": False},
            ensure_ascii=False,
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            request = urllib.request.Request(settings["api_url"], body, headers, method="POST")
            with urllib.request.urlopen(request, timeout=settings["timeout_seconds"]) as response:
                status_code = response.getcode()
                raw = response.read()
            if status_code < 200 or status_code >= 300:
                return self._unavailable(provider, settings["model_name"], request_sent=True)
            payload = json.loads(raw.decode("utf-8"))
            content = self._response_content(payload)
            if not content:
                return self._unavailable(provider, settings["model_name"], request_sent=True)
            return LLMResult(content, provider, settings["model_name"], "ok", True)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ):
            return self._unavailable(provider, settings["model_name"], request_sent=True)

    def _settings(self) -> dict[str, Any] | None:
        try:
            config = self._config.get()
        except (OSError, ValueError, TypeError):
            return None
        if not isinstance(config, dict):
            return None
        provider = str(config.get("provider", "")).strip()
        if provider not in SUPPORTED_PROVIDERS:
            return None
        model_name = str(config.get("model_name", "")).strip()
        api_url = str(config.get("api_url", "")).strip()
        api_key_env = str(config.get("api_key_env", "")).strip()
        try:
            timeout_seconds = float(config.get("timeout_seconds", 0))
        except (TypeError, ValueError):
            timeout_seconds = 0.0
        return {
            "provider": provider,
            "api_url": api_url,
            "model_name": model_name,
            "timeout_seconds": timeout_seconds,
            "api_key_env": api_key_env,
        }

    @staticmethod
    def _api_key() -> str:
        return os.getenv(API_KEY_ENV_NAME, "").strip()

    @staticmethod
    def _response_content(payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            return ""
        message = choices[0].get("message")
        if not isinstance(message, dict):
            return ""
        content = message.get("content")
        return content.strip() if isinstance(content, str) else ""

    @staticmethod
    def _unavailable(provider: str, model_name: str, request_sent: bool) -> LLMResult:
        return LLMResult(UNAVAILABLE_RESPONSE, provider, model_name, "unavailable", request_sent)

    @staticmethod
    def _real_settings_valid(settings: dict[str, Any]) -> bool:
        if (
            not settings["model_name"]
            or settings["api_key_env"] != API_KEY_ENV_NAME
        ):
            return False
        timeout = settings["timeout_seconds"]
        if not isinstance(timeout, float) or not 0 < timeout <= 120:
            return False
        parsed = urlparse(settings["api_url"])
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        if settings["provider"] == "deepseek":
            return parsed.scheme == "https" or parsed.hostname.lower() in LOOPBACK_HOSTS
        return True
