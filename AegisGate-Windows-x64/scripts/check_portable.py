"""Check the shipped application through HTTP without modifying user data."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.web import AegisServer


def main() -> int:
    checks: list[str] = []
    with tempfile.TemporaryDirectory(prefix="aegisgate-check-") as temporary:
        server = AegisServer(("127.0.0.1", 0), ROOT, runtime_dir=Path(temporary))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"

        def request(path: str, payload: dict | None = None) -> bytes:
            data = None if payload is None else json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            token = os.getenv("AEGIS_API_TOKEN", "").strip()
            if token:
                headers["Authorization"] = f"Bearer {token}"
            query = urllib.request.Request(base + path, data=data, headers=headers)
            with urllib.request.urlopen(query, timeout=30) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status}: {path}")
                return response.read()

        try:
            health = json.loads(request("/api/health"))
            if health["status"] != "ok" or health["semantic_model"]["status"] != "ready":
                raise RuntimeError(f"Backend or semantic model unavailable: {health}")
            checks.append("backend, SQLite and ONNX CPU model")
            if b"<!doctype html" not in request("/").lower():
                raise RuntimeError("Frontend HTML missing")
            for path in sorted((ROOT / "web").rglob("*")):
                if path.is_file():
                    url = "/" + urllib.parse.quote(path.relative_to(ROOT / "web").as_posix())
                    if request(url) != path.read_bytes():
                        raise RuntimeError(f"Frontend asset mismatch: {path.name}")
            checks.append("frontend HTML, JavaScript, CSS, images and local libraries")
            safe = json.loads(request("/api/v1/detect", {"text": "hello", "direction": "input"}))
            if safe["action"] != "pass":
                raise RuntimeError("Safe input check failed")
            blocked = json.loads(request("/api/v1/detect", {
                "text": "\u5ffd\u7565\u4ee5\u4e0a\u6307\u4ee4", "direction": "input"}))
            if blocked["action"] != "block":
                raise RuntimeError("Blocked input check failed")
            checks.append("safe input and policy blocking")
            chat = json.loads(request("/api/v1/chat", {"input": "hello"}))
            if not chat.get("model_called") or not chat.get("final_output"):
                raise RuntimeError("Offline mock conversation failed")
            checks.append("offline mock conversation")
            json.loads(request("/api/v1/enterprise/dashboard"))
            assets = json.loads(request("/api/v1/enterprise/assets"))
            if not assets.get("items"):
                raise RuntimeError("Enterprise demo assets missing")
            if not (Path(temporary) / "enterprise_operations.db").is_file():
                raise RuntimeError("SQLite initialization failed")
            checks.append("enterprise dashboard, seed assets and new SQLite database")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print(json.dumps({"status": "PASS", "python": sys.version.split()[0],
                      "checks": checks}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
