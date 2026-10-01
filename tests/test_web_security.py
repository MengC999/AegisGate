from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.web import AegisServer  # noqa: E402


class WebSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="aegis-web-security-")
        cls.test_root = Path(cls.temporary.name)
        (cls.test_root / "config").mkdir(parents=True)
        (cls.test_root / "data").mkdir()
        (cls.test_root / "web").mkdir()
        (cls.test_root / "config" / "api_config.json").write_text(
            json.dumps(
                {
                    "provider": "mock",
                    "api_url": "",
                    "model_name": "aegis-offline-mock",
                    "timeout_seconds": 1,
                    "api_key_env": "DEEPSEEK_API_KEY",
                }
            ),
            encoding="utf-8",
        )
        (cls.test_root / "config" / "safety_policy.json").write_text(
            json.dumps(
                {
                    "version": "security-test",
                    "limits": {
                        "max_text_chars": 8000,
                        "max_history_turns": 2,
                        "max_request_bytes": 24576,
                    },
                    "thresholds": {"pass": 0.35, "mask": 0.58, "block": 0.82},
                    "category_names": {},
                    "maskable_categories": ["pii", "fraud"],
                    "context_reducers": {},
                    "safe_replies": {
                        "block": "安全拦截",
                        "review": "等待复核",
                        "support": "安全关怀",
                        "output_block": "输出已替换",
                    },
                    "regex_rules": [],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        (cls.test_root / "data" / "keyword_library_v2.json").write_text(
            json.dumps({"version": "test", "categories": {}}),
            encoding="utf-8",
        )
        (cls.test_root / "web" / "index.html").write_text(
            "<!doctype html><title>AegisGate test</title>",
            encoding="utf-8",
        )
        with patch.dict(os.environ, {"AEGIS_API_TOKEN": ""}):
            cls.server = AegisServer(
                ("127.0.0.1", 0),
                cls.test_root,
                runtime_dir=cls.test_root / "runtime",
            )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.temporary.cleanup()

    def request_error(
        self,
        path: str,
        payload: dict[str, object],
    ) -> tuple[int, dict[str, object]]:
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=3)
        body = json.loads(raised.exception.read().decode("utf-8"))
        status = raised.exception.code
        raised.exception.close()
        return status, body

    def test_chat_history_requires_an_exact_string_list(self) -> None:
        invalid_histories: list[object] = [None, "", {}, ["正常轮次", 1]]
        for history in invalid_histories:
            with self.subTest(history=history):
                status, body = self.request_error(
                    "/api/v1/chat",
                    {"input": "整理会议纪要", "history": history},
                )
                self.assertEqual(status, 400)
                self.assertEqual(body["error"]["code"], "INVALID_REQUEST")
                self.assertEqual(body["error"]["message"], "history 必须是字符串数组")

    def test_chat_history_over_limit_is_explicitly_rejected(self) -> None:
        status, body = self.request_error(
            "/api/v1/chat",
            {"input": "整理会议纪要", "history": ["第一轮", "第二轮", "第三轮"]},
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["message"], "history 最多允许 2 轮")

    def test_omitted_and_valid_history_remain_supported(self) -> None:
        for payload in (
            {"input": "整理会议纪要"},
            {"input": "整理会议纪要", "history": ["第一轮", "第二轮"]},
        ):
            with self.subTest(payload=payload):
                request = urllib.request.Request(
                    self.base + "/api/v1/chat",
                    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=3) as response:
                    body = json.loads(response.read().decode("utf-8"))
                self.assertEqual(response.status, 200)
                self.assertIn(body["action"], {"pass", "input_mask"})

    def test_non_loopback_bind_requires_a_token(self) -> None:
        unprotected = None
        try:
            with patch.dict(os.environ, {"AEGIS_API_TOKEN": ""}):
                with self.assertRaisesRegex(ValueError, "AEGIS_API_TOKEN"):
                    unprotected = AegisServer(("0.0.0.0", 0), self.test_root)
        finally:
            if unprotected is not None:
                unprotected.server_close()

        with patch.dict(os.environ, {"AEGIS_API_TOKEN": "   "}):
            with self.assertRaisesRegex(ValueError, "AEGIS_API_TOKEN"):
                AegisServer(("::", 0), self.test_root)

    def test_remote_server_captures_token_and_enforces_bearer_auth(self) -> None:
        token = "fixed-test-api-token"
        with patch.dict(os.environ, {"AEGIS_API_TOKEN": token}):
            server = AegisServer(
                ("0.0.0.0", 0),
                self.test_root,
                runtime_dir=self.test_root / "remote-runtime",
            )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with patch.dict(os.environ, {"AEGIS_API_TOKEN": ""}):
                for path in ("/api/health", "/api/v1/model/status"):
                    with self.subTest(path=path):
                        with self.assertRaises(urllib.error.HTTPError) as raised:
                            urllib.request.urlopen(base + path, timeout=3)
                        self.assertEqual(raised.exception.code, 401)
                        unauthorized_body = raised.exception.read().decode("utf-8")
                        raised.exception.close()
                        self.assertNotIn(token, unauthorized_body)

                authenticated = urllib.request.Request(
                    base + "/api/v1/model/status",
                    headers={"Authorization": f"Bearer {token}"},
                )
                with urllib.request.urlopen(authenticated, timeout=3) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(payload["provider"], "mock")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_access_log_excludes_query_and_authorization(self) -> None:
        query_secret = "QUERY_SECRET_MARKER"
        header_secret = "HEADER_SECRET_MARKER"
        output = io.StringIO()
        request = urllib.request.Request(
            self.base + f"/api/health?probe={query_secret}",
            headers={"Authorization": f"Bearer {header_secret}"},
        )
        with contextlib.redirect_stdout(output):
            with urllib.request.urlopen(request, timeout=3) as response:
                response.read()
        access_log = output.getvalue()
        self.assertIn("/api/health", access_log)
        self.assertNotIn(query_secret, access_log)
        self.assertNotIn(header_secret, access_log)

    def test_validation_and_protocol_errors_do_not_echo_input(self) -> None:
        marker = "ATTACKER_CONTROLLED_EXCEPTION_MARKER"
        with patch.object(self.server.service, "stats", side_effect=ValueError(marker)):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(self.base + "/api/v1/stats", timeout=3)
            body = raised.exception.read().decode("utf-8")
        self.assertEqual(raised.exception.code, 400)
        raised.exception.close()

        self.assertNotIn(marker, body)
        self.assertEqual(
            json.loads(body)["error"],
            {"code": "INVALID_REQUEST", "message": "请求参数无效"},
        )

        method_marker = "TRACE-ATTACKER-MARKER"
        request = urllib.request.Request(
            self.base + "/api/health?ignored=1",
            method=method_marker,
        )
        protocol_log = io.StringIO()
        with contextlib.redirect_stdout(protocol_log):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=3)
        protocol_body = raised.exception.read().decode("utf-8")
        self.assertEqual(raised.exception.code, 501)
        self.assertNotIn("Python", raised.exception.headers.get("Server", ""))
        raised.exception.close()
        self.assertNotIn(method_marker, protocol_body)
        self.assertNotIn(method_marker, protocol_log.getvalue())
        self.assertEqual(
            json.loads(protocol_body)["error"],
            {"code": "HTTP_ERROR", "message": "不支持的请求方法"},
        )

    def test_chat_input_requires_non_empty_string(self) -> None:
        for payload in ({}, {"input": ""}, {"input": 123}):
            with self.subTest(payload=payload):
                request = urllib.request.Request(
                    self.base + "/api/v1/chat",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=3)
                self.assertEqual(raised.exception.code, 400)
                raised.exception.close()


if __name__ == "__main__":
    unittest.main()
