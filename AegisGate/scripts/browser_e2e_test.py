#!/usr/bin/env python3
"""Run the keyword and statistics journey in a real local Chromium browser."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.aegisguard.policy import KeywordLibrary  # noqa: E402
from src.aegisguard.web import AegisServer  # noqa: E402


class QuietAegisServer(AegisServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


def find_browser() -> Path | None:
    configured = os.getenv("AEGIS_BROWSER_PATH", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        return candidate.resolve() if candidate.is_file() else None
    for name in (
        "google-chrome",
        "chrome",
        "chromium",
        "chromium-browser",
        "msedge",
        "microsoft-edge",
    ):
        executable = shutil.which(name)
        if executable:
            return Path(executable).resolve()
    candidates: list[Path] = []
    if os.name == "nt":
        roots = [
            os.environ.get("ProgramFiles", ""),
            os.environ.get("ProgramFiles(x86)", ""),
            os.environ.get("LOCALAPPDATA", ""),
        ]
        for root in roots:
            if not root:
                continue
            base = Path(root)
            candidates.extend(
                [
                    base / "Google" / "Chrome" / "Application" / "chrome.exe",
                    base / "Microsoft" / "Edge" / "Application" / "msedge.exe",
                ]
            )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


class DevToolsWebSocket:
    def __init__(self, url: str, timeout: float = 15.0) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "ws" or not parsed.hostname:
            raise ValueError("DevTools WebSocket 地址无效")
        self.socket = socket.create_connection(
            (parsed.hostname, parsed.port or 80),
            timeout=timeout,
        )
        self.socket.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port or 80}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode("ascii"))
        response = self._read_headers()
        if not response.startswith(b"HTTP/1.1 101"):
            raise RuntimeError("DevTools WebSocket 握手失败")
        accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")
        if f"sec-websocket-accept: {accept}".lower() not in response.decode(
            "latin-1"
        ).lower():
            raise RuntimeError("DevTools WebSocket 握手校验失败")
        self.next_id = 1

    def close(self) -> None:
        try:
            self._send_frame(b"", opcode=8)
        except OSError:
            pass
        self.socket.close()

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self._send_frame(
            json.dumps(
                {"id": request_id, "method": method, "params": params or {}},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        while True:
            payload = self._receive_text()
            message = json.loads(payload)
            if message.get("id") != request_id:
                continue
            if "error" in message:
                error = message["error"]
                raise RuntimeError(
                    f"DevTools 调用失败: {method}; "
                    f"code={error.get('code')}; message={str(error.get('message', ''))[:120]}"
                )
            return message.get("result", {})

    def _read_headers(self) -> bytes:
        chunks = bytearray()
        while b"\r\n\r\n" not in chunks:
            chunks.extend(self.socket.recv(4096))
            if len(chunks) > 65536:
                raise RuntimeError("DevTools 握手响应过长")
        return bytes(chunks)

    def _send_frame(self, payload: bytes, opcode: int = 1) -> None:
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.socket.sendall(bytes(header) + mask + masked)

    def _receive_text(self) -> str:
        fragments = bytearray()
        while True:
            first, second = self._read_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if second & 0x80 else b""
            payload = self._read_exact(length)
            if mask:
                payload = bytes(
                    value ^ mask[index % 4] for index, value in enumerate(payload)
                )
            if opcode == 8:
                raise RuntimeError("DevTools WebSocket 已关闭")
            if opcode == 9:
                self._send_frame(payload, opcode=10)
                continue
            if opcode in {0, 1}:
                fragments.extend(payload)
                if final:
                    return fragments.decode("utf-8")

    def _read_exact(self, length: int) -> bytes:
        output = bytearray()
        while len(output) < length:
            chunk = self.socket.recv(length - len(output))
            if not chunk:
                raise RuntimeError("DevTools WebSocket 意外断开")
            output.extend(chunk)
        return bytes(output)


def _wait_devtools(profile: Path, timeout: float = 15.0) -> tuple[int, str]:
    active_port = profile / "DevToolsActivePort"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if active_port.is_file():
                lines = active_port.read_text(encoding="utf-8").splitlines()
                if lines:
                    return int(lines[0]), lines[1] if len(lines) > 1 else ""
        except OSError:
            pass
        time.sleep(0.05)
    raise TimeoutError("Chromium DevTools 未就绪")


def _page_websocket(port: int, timeout: float = 15.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as response:
                targets = json.load(response)
            for target in targets:
                if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
                    return str(target["webSocketDebuggerUrl"])
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    raise TimeoutError("未找到 Chromium 页面调试目标")


def _evaluate(socket_client: DevToolsWebSocket, expression: str) -> Any:
    result = socket_client.call(
        "Runtime.evaluate",
        {
            "expression": expression,
            "awaitPromise": True,
            "returnByValue": True,
        },
    )
    if result.get("exceptionDetails"):
        details = result["exceptionDetails"]
        exception = details.get("exception", {}) if isinstance(details, dict) else {}
        description = exception.get("description") or details.get("text") or "未知页面异常"
        raise RuntimeError(f"浏览器页面脚本执行失败: {description[:220]}")
    return result.get("result", {}).get("value")


def _wait_page_ready(
    socket_client: DevToolsWebSocket,
    expected_url: str,
    timeout: float = 15.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            state = _evaluate(
                socket_client,
                "[location.href, document.readyState]",
            )
            if (
                isinstance(state, list)
                and str(state[0]).startswith(expected_url)
                and state[1] == "complete"
            ):
                time.sleep(0.1)
                return
        except RuntimeError as exc:
            if "Execution context was destroyed" not in str(exc):
                raise
        time.sleep(0.05)
    raise TimeoutError("浏览器页面加载超时")


E2E_EXPRESSION = r"""
(async () => {
  const requiredToken = __E2E_API_TOKEN__;
  const waitFor = async (check, label) => {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      if (check()) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`等待超时: ${label}`);
  };
  if (requiredToken) {
    await waitFor(() => document.querySelector('#accessTokenDialog')?.open, '访问令牌连接框');
    document.querySelector('#accessTokenInput').value = requiredToken;
    document.querySelector('#accessTokenForm').requestSubmit();
  }
  await waitFor(() => document.querySelector('#healthText')?.textContent.includes('mock'), '初始化');
  const officialCards = document.querySelectorAll('[data-official-category]').length;
  if (officialCards !== 4) throw new Error('官方四类卡片数量错误');
  if (!document.querySelector('#overviewProvider')?.textContent.includes('mock')) throw new Error('Provider 未展示');
  if (!document.querySelector('#overviewModelName')?.textContent.includes('aegis')) throw new Error('Model Name 未展示');
  const semanticStatus = document.querySelector('#overviewSemanticStatus')?.textContent.trim();
  if (!['ready', 'unavailable', 'invalid'].includes(semanticStatus)) throw new Error('语义模型状态未展示');

  const runSample = async (sample, expectedAction) => {
    document.querySelector(`[data-sample="${sample}"]`).click();
    document.querySelector('#testForm').requestSubmit();
    await waitFor(() => document.querySelector('#resultTitle')?.textContent === expectedAction && !document.querySelector('#modelForwarding').textContent.includes('尚未'), `检测结果 ${expectedAction}`);
  };
  await runSample('normal', '正常放行');
  if (!document.querySelector('#modelForwarding').textContent.includes('未转发')) throw new Error('单段检测转发状态错误');
  await runSample('obfuscated', '安全拦截');
  await runSample('privacy', '自动脱敏');
  await runSample('output', '人工复核');
  if (document.querySelector('#modelForwarding').textContent !== '已转发模型') throw new Error('双向流程未展示模型转发');
  if (document.querySelector('#outputReviewStatus').textContent !== '已执行输出复检') throw new Error('双向流程未展示输出复检');
  if (document.querySelector('#backendTraceStatus').textContent !== '后端已响应') throw new Error('未展示后端响应状态');
  if (!document.querySelector('#backendEndpoint').textContent.includes('POST /api/v1/chat')) throw new Error('未展示真实后端接口');
  if (!document.querySelector('#backendRequestId').textContent.includes('HTTP 请求 ID')) throw new Error('未展示后端请求标识');
  if (!document.querySelector('#backendAudit').textContent.includes('审计链完整')) throw new Error('未展示审计落盘状态');

  const addedTerm = '浏览器星河回归词';
  const importedTerm = '浏览器霜刃回归词';
  document.querySelector('[data-view="rules"]').click();
  await waitFor(() => !document.querySelector('#view-rules').hidden, '词库视图切换');
  const category = document.querySelector('#keywordCategory');
  category.value = 'advertising';
  category.dispatchEvent(new Event('change', { bubbles: true }));
  document.querySelector('#keywordTerm').value = addedTerm;
  document.querySelector('#keywordForm').requestSubmit();
  await waitFor(() => document.querySelector('#keywordList').textContent.includes(addedTerm), '添加词条');

  document.querySelector('#inputText').value = `请识别${addedTerm}`;
  document.querySelector('#inputText').dispatchEvent(new Event('input', { bubbles: true }));
  document.querySelector('#testForm').requestSubmit();
  await waitFor(() => Number(document.querySelector('#officialAdvertisingCount').textContent) >= 1, '统计刷新');

  const file = new File(
    [JSON.stringify({ categories: { violence: [importedTerm] } })],
    'browser-import.json',
    { type: 'application/json' },
  );
  const transfer = new DataTransfer();
  transfer.items.add(file);
  const input = document.querySelector('#keywordImportFile');
  input.files = transfer.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  await waitFor(() => document.querySelector('#toast').textContent.includes('导入完成'), '导入词库');
  category.value = 'violence';
  category.dispatchEvent(new Event('change', { bubbles: true }));
  await waitFor(() => document.querySelector('#keywordList').textContent.includes(importedTerm), '导入生效');

  input.files = transfer.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  await waitFor(() => document.querySelector('#importResult').textContent.includes('重复'), '重复项提示');

  input.files = new DataTransfer().files;
  const invalid = new File(['{not-json'], 'invalid.json', { type: 'application/json' });
  const invalidTransfer = new DataTransfer();
  invalidTransfer.items.add(invalid);
  input.files = invalidTransfer.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  await waitFor(() => document.querySelector('#importResult').classList.contains('error'), '导入失败状态');
  const afterInvalidImport = await api('/api/v1/keywords');
  if (!afterInvalidImport.categories.violence.terms.includes(importedTerm)) throw new Error('失败导入影响了原词库');

  category.value = 'advertising';
  category.dispatchEvent(new Event('change', { bubbles: true }));
  const remove = [...document.querySelectorAll('.keyword-remove')]
    .find((button) => button.getAttribute('aria-label') === `删除词条：${addedTerm}`);
  if (!remove) throw new Error('未找到删除按钮');
  remove.click();
  await waitFor(() => document.querySelector('#deleteConfirmDialog').open, '删除确认');
  document.querySelector('#confirmDeleteButton').click();
  await waitFor(() => !document.querySelector('#keywordList').textContent.includes(addedTerm), '删除词条');

  document.querySelector('[data-view="audit"]').click();
  await waitFor(() => !document.querySelector('#view-audit').hidden, '审计视图切换');
  document.querySelector('#auditRefreshButton').click();
  await waitFor(() => Number(document.querySelector('#auditTotal').textContent) > 0, '统计刷新');
  if (!document.querySelector('#auditChainStatus').textContent.includes('哈希链')) throw new Error('审计链状态未展示');
  document.querySelector('#verifyButton').click();
  await waitFor(() => document.querySelector('#toast').textContent.includes('审计链'), '审计链校验');

  document.querySelector('[data-view="ops"]').click();
  await waitFor(() => !document.querySelector('#enterpriseDashboardPanel').classList.contains('hidden') && Number(document.querySelector('#enterpriseTodoCount').textContent.match(/\d+/)?.[0] || 0) > 0, '企业运营工作台');
  if (document.querySelector('#enterpriseWorkbenchHeading')?.textContent !== '运营总览') throw new Error('运营总览未展示');
  if (document.querySelectorAll('.view-panel:not([hidden])').length !== 1) throw new Error('多个运营页面同时显示');
  if (document.querySelectorAll('#enterpriseAlertTrend .enterprise-trend-column').length !== 14) throw new Error('告警趋势未完整渲染');
  if (document.querySelectorAll('#enterpriseVulnerabilityTrend .enterprise-trend-column').length !== 14) throw new Error('漏洞趋势未完整渲染');
  document.querySelector('[data-view="ops-risks"]').click();
  await waitFor(() => !document.querySelector('#enterpriseResourcePanel').classList.contains('hidden') && document.querySelector('#enterpriseResourceTitle').textContent.includes('漏洞'), '企业漏洞管理');
  if (!document.querySelector('#enterpriseTableBody').textContent.includes('CVE-2026-10001')) throw new Error('企业漏洞记录未展示');
  document.querySelector('[data-view="ops-reports"]').click();
  await waitFor(() => !document.querySelector('#enterpriseResourcePanel').classList.contains('hidden') && document.querySelector('#enterpriseResourceTitle').textContent.includes('报表'), '企业报表归档');
  document.querySelector('[data-view="ops"]').click();
  await waitFor(() => !document.querySelector('#enterpriseDashboardPanel').classList.contains('hidden'), '企业运营总览恢复');
  document.querySelector('[data-view="ops-history"]').click();
  await waitFor(() => document.querySelector('#opsAssetsCount').textContent === '3', '历史运营台账');
  if (document.querySelector('#opsOpenAlerts').textContent !== '2') throw new Error('运营告警数量未展示');
  document.querySelector('[data-ops-resource="alerts"]').click();
  await waitFor(() => !document.querySelector('#opsTablePanel').classList.contains('hidden') && document.querySelector('#opsTableBody').textContent.includes('Sensitive identifier'), '告警列表');
  if (!document.querySelector('#opsTableBody').textContent.includes('Sensitive identifier')) throw new Error('告警列表未展示脱敏摘要');
  document.querySelector('#opsCreateButton').click();
  document.querySelector('#opsCreateResource').value = 'iocs';
  document.querySelector('#opsCreateTitle').value = '浏览器回归 IOC';
  document.querySelector('#opsCreateValue').value = '192.0.2.88';
  document.querySelector('#opsCreateSource').value = '授权 E2E 测试';
  document.querySelector('#opsCreateForm').requestSubmit();
  await waitFor(() => document.querySelector('#toast').textContent.includes('记录已登记'), '登记运营记录');
  const operationsAudit = await (await fetch('/api/v1/ops/events/verify')).json();
  if (!operationsAudit.valid) throw new Error('运营事件链校验失败');

  document.querySelector('[data-view="system"]').click();
  await waitFor(() => !document.querySelector('#view-system').hidden, '系统视图切换');
  if (!document.querySelector('#systemProvider').textContent.includes('mock')) throw new Error('系统 Provider 未展示');
  if (!['ready', 'unavailable', 'invalid'].includes(document.querySelector('#systemSemanticStatus').textContent.trim())) throw new Error('系统语义模型状态未展示');

  const keywords = await (await fetch('/api/v1/keywords')).json();
  const advertisingTerms = keywords.categories.fraud.terms;
  const violenceTerms = keywords.categories.violence.terms;
  return {
    status: 'success',
    browser_dom_ready: document.readyState === 'complete',
    provider: document.querySelector('#healthText').textContent.split(' · ')[0],
    official_cards: officialCards,
    added_then_removed: !advertisingTerms.includes(addedTerm),
    imported_and_persisted: violenceTerms.includes(importedTerm),
    detection_action: 'normal/block/mask/output_review',
    operations_workspace: true,
    enterprise_trends: true,
    operations_audit_chain: operationsAudit.entries,
    advertising_count: Number(document.querySelector('#officialAdvertisingCount').textContent),
    audit_chain: document.querySelector('#auditChainStatus').textContent,
    semantic_model_status: document.querySelector('#systemSemanticStatus').textContent,
  };
})()
"""


def _check_layouts(client: DevToolsWebSocket) -> dict[str, dict[str, int]]:
    layouts: dict[str, dict[str, int]] = {}
    for width, height in ((1440, 900), (1280, 800), (768, 1024), (500, 900)):
        client.call(
            "Emulation.setDeviceMetricsOverride",
            {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False},
        )
        time.sleep(0.15)
        for view in ("detect", "rules", "audit", "ops", "ops-assets", "ops-response", "ops-risks", "ops-maintenance", "ops-reports", "ops-access", "ops-settings", "ops-history", "system"):
            _evaluate(client, f"document.querySelector('[data-view=\\\"{view}\\\"]').click()")
            time.sleep(0.05)
            metrics = _evaluate(
                client,
                "[innerWidth, innerHeight, document.documentElement.scrollWidth, document.body.scrollWidth]",
            )
            if not isinstance(metrics, list) or len(metrics) != 4:
                raise RuntimeError(f"{width}x{height} {view} 布局尺寸读取失败")
            inner_width = int(metrics[0])
            scroll_width = max(int(metrics[2]), int(metrics[3]))
            if scroll_width > inner_width + 1:
                raise RuntimeError(f"{width}x{height} {view} 存在横向溢出: {scroll_width}>{inner_width}")
        layouts[f"{width}x{height}"] = {"inner_width": int(metrics[0]), "inner_height": int(metrics[1]), "scroll_width": scroll_width}
    client.call("Emulation.clearDeviceMetricsOverride")
    _evaluate(client, "document.querySelector('[data-view=\\\"detect\\\"]').click()")
    return layouts


def main() -> int:
    browser = find_browser()
    if browser is None:
        print(json.dumps({"status": "unavailable", "reason": "browser_not_found"}))
        return 2

    with tempfile.TemporaryDirectory(prefix="aegis-browser-e2e-") as temporary:
        workspace = Path(temporary)
        keyword_path = workspace / "keyword_library.json"
        shutil.copyfile(ROOT / "data" / "keyword_library_v2.json", keyword_path)
        token = os.getenv("AEGIS_BROWSER_E2E_TOKEN", "").strip()
        with patch.dict(os.environ, {"AEGIS_API_TOKEN": token}):
            server = QuietAegisServer(
                ("127.0.0.1", 0),
                ROOT,
                runtime_dir=workspace / "runtime",
            )
        server.service.engine.keywords = KeywordLibrary(keyword_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        profile = workspace / "browser-profile"
        profile.mkdir()
        process = subprocess.Popen(
            [
                str(browser),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-port=0",
                f"--user-data-dir={profile}",
                f"http://127.0.0.1:{server.server_port}/",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        client: DevToolsWebSocket | None = None
        try:
            port, _ = _wait_devtools(profile)
            client = DevToolsWebSocket(_page_websocket(port))
            client.call("Runtime.enable")
            _wait_page_ready(
                client,
                f"http://127.0.0.1:{server.server_port}/",
            )
            expression = E2E_EXPRESSION.replace("__E2E_API_TOKEN__", json.dumps(token))
            result = _evaluate(client, expression)
            if not isinstance(result, dict) or result.get("status") != "success":
                raise RuntimeError("浏览器 E2E 返回结构无效")
            result["viewports"] = _check_layouts(client)
            result["background_image"] = _evaluate(
                client,
                "getComputedStyle(document.body, '::before').backgroundImage",
            )
            result["background_asset_loaded"] = _evaluate(
                client,
                "Array.from(performance.getEntriesByType('resource')).some((entry) => entry.name.includes('glass-architecture.svg'))",
            )
            if "glass-architecture.svg" not in str(result["background_image"]):
                raise RuntimeError("工作台背景计算样式未加载原创 SVG 背景")
            if result["background_asset_loaded"] is not True:
                raise RuntimeError("工作台背景资源未出现在浏览器资源记录中")
            result["glass_surfaces"] = _evaluate(
                client,
                """(() => {
                  const selectors = ['.topbar', '.view-tabs', '.tool-panel', '.enterprise-workbench', '#enterpriseResourcePanel'];
                  return selectors.map((selector) => {
                    const node = document.querySelector(selector);
                    if (!node) return { selector, background: null };
                    const style = getComputedStyle(node);
                    return { selector, background: style.backgroundColor, image: style.backgroundImage };
                  });
                })()""",
            )
            opaque_surfaces = [
                item for item in result["glass_surfaces"]
                if item.get("background") not in ("rgba(0, 0, 0, 0)", "transparent")
            ]
            if opaque_surfaces:
                raise RuntimeError(f"玻璃面板仍存在有色背景: {opaque_surfaces}")
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "status": "failed",
                        "reason": type(exc).__name__,
                        "detail": str(exc)[:160],
                    },
                    ensure_ascii=False,
                )
            )
            return 1
        finally:
            if client is not None:
                client.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
