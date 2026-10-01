#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.web import AegisServer  # noqa: E402


def find_browser() -> Path | None:
    configured = os.getenv("AEGIS_BROWSER_PATH", "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path.resolve()
    for name in ("msedge", "microsoft-edge", "google-chrome", "chrome", "chromium", "chromium-browser"):
        executable = shutil.which(name)
        if executable:
            return Path(executable).resolve()
    return None


def capture(browser: Path, url: str, target: Path, size: str) -> None:
    profile = Path(tempfile.mkdtemp(prefix="aegis-browser-"))
    try:
        command = [
            str(browser), "--headless=new", "--disable-gpu", "--hide-scrollbars",
            "--run-all-compositor-stages-before-draw", "--virtual-time-budget=3500",
            f"--window-size={size}", "--force-device-scale-factor=1",
            f"--user-data-dir={profile}", f"--screenshot={target}", url,
        ]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def main() -> int:
    browser = find_browser()
    if not browser:
        print("未在 PATH 中找到 Chromium 浏览器；可设置 AEGIS_BROWSER_PATH 后重试。")
        return 2
    server = AegisServer(("127.0.0.1", 0), ROOT)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    output = ROOT / "screenshots"
    output.mkdir(exist_ok=True)
    try:
        capture(browser, f"{base}/?demo=obfuscated", output / "01_混淆注入_桌面.png", "1440,1100")
        capture(browser, f"{base}/?demo=output", output / "02_输出复检_桌面.png", "1440,1100")
        capture(browser, f"{base}/?demo=sequence", output / "04_多轮时序_桌面.png", "1440,1200")
        capture(browser, f"{base}/?demo=batch", output / "06_批量治理_桌面.png", "1440,1100")
        capture(browser, f"{base}/?view=ops", output / "07_安全运营_桌面.png", "1440,1100")
        # Chromium headless enforces an internal minimum layout width near 500 px.
        capture(browser, f"{base}/?demo=privacy", output / "03_隐私脱敏_移动端.png", "500,900")
        capture(browser, f"{base}/?demo=sequence", output / "05_多轮时序_移动端.png", "500,1800")
        capture(browser, f"{base}/?view=ops", output / "08_安全运营_移动端.png", "500,1400")
        # Dedicated visual-regression captures for the 4K landscape background.
        capture(browser, f"{base}/?view=ops", output / "09_视觉重构_桌面.png", "1440,900")
        capture(browser, f"{base}/?view=ops", output / "10_视觉重构_移动端.png", "500,900")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    for path in sorted(output.glob("*.png")):
        print(f"{path.name}: {path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
