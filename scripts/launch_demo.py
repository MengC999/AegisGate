#!/usr/bin/env python3
"""Start the local demo first, then open the browser after the port is bound."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.web import AegisServer  # noqa: E402


MINIMUM_PYTHON = (3, 10)


def create_server(
    host: str,
    preferred_port: int,
    runtime_dir: Path | None = None,
    model_config_path: Path | None = None,
) -> tuple[AegisServer, bool]:
    """Use the preferred local port, then fall back to the next ten ports."""
    try:
        return AegisServer((host, preferred_port), ROOT, runtime_dir=runtime_dir, model_config_path=model_config_path), False
    except OSError as original_error:
        for port in range(preferred_port + 1, preferred_port + 11):
            try:
                return AegisServer((host, port), ROOT, runtime_dir=runtime_dir, model_config_path=model_config_path), True
            except OSError:
                continue
        raise original_error


def health_check(host: str, runtime_dir: Path | None = None, model_config_path: Path | None = None) -> int:
    server, _ = create_server(host, 0, runtime_dir=runtime_dir, model_config_path=model_config_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(f"http://{host}:{server.server_port}/api/health")
        token = os.getenv("AEGIS_API_TOKEN", "").strip()
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = response.read().decode("utf-8")
        print(f"本地服务自检通过：{payload}")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> int:
    if sys.version_info[:2] < MINIMUM_PYTHON:
        required = ".".join(str(part) for part in MINIMUM_PYTHON)
        current = ".".join(str(part) for part in sys.version_info[:3])
        print(f"Python {required} 或更高版本才能运行；当前版本为 {current}。")
        return 2
    parser = argparse.ArgumentParser(description="启动 AegisGate 本地演示")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--model-config", type=Path, default=None, help="使用独立模型配置文件")
    parser.add_argument("--health-check", action="store_true", help="启动临时服务并验证健康接口后退出")
    parser.add_argument(
        "--runtime-dir",
        type=Path,
        default=None,
        help="指定本次运行的审计/复核目录；适合现场演示",
    )
    args = parser.parse_args()
    if args.health_check:
        try:
            return health_check(args.host, runtime_dir=args.runtime_dir, model_config_path=args.model_config)
        except (OSError, ValueError) as exc:
            print(f"本地服务自检失败：{exc}")
            return 1
    try:
        server, used_fallback_port = create_server(
            args.host,
            args.port,
            runtime_dir=args.runtime_dir,
            model_config_path=args.model_config,
        )
    except (OSError, ValueError) as exc:
        print(f"无法启动本地服务：{exc}")
        print("请确认防火墙或安全软件未阻止本机 Python 服务。")
        return 1

    address = f"http://{args.host}:{server.server_port}"
    if used_fallback_port:
        print(f"端口 {args.port} 已占用，已自动切换到 {server.server_port}。")
    print(f"AegisGate 已启动：{address}")
    print("关闭此窗口即可停止本地演示服务。")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(address, new=2)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
