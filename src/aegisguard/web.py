from __future__ import annotations

import hmac
import ipaddress
import json
import mimetypes
import os
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .enterprise import (
    EnterpriseConflictError,
    EnterpriseNotFoundError,
    EnterpriseValidationError,
)
from .service import ConversationService
from .operations import OperationsValidationError
from .openapi import build_openapi
from .routing import (
    RoutingError,
    RoutingManager,
    RoutingPolicyError,
    RoutingReplayError,
    RoutingSignatureError,
)
from .telemetry import TelemetryScopeError
from .invention_evidence import EvidenceScopeError


LOGGABLE_METHODS = {"GET", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS"}


class RequestValidationError(ValueError):
    """A validation failure whose message is fixed by this server."""


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


class RateLimiter:
    def __init__(self, maximum: int = 120, window_seconds: int = 60) -> None:
        self.maximum = maximum
        self.window_seconds = window_seconds
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            now = time.monotonic()
            bucket = self.hits[key]
            while bucket and bucket[0] < now - self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.maximum:
                return False
            bucket.append(now)
            return True


ROLE_PERMISSIONS = {
    "admin": {"read", "write", "review", "manage"},
    "operator": {"read", "write"},
    "reviewer": {"read", "review"},
    "readonly": {"read"},
}
_SCOPE_VALUE = re.compile(r"[a-z][a-z0-9_-]{2,63}")


class AegisServer(ThreadingHTTPServer):
    # Keep request workers non-daemon so shutdown waits for the final SQLite
    # transaction before temporary test/runtime directories are removed.
    daemon_threads = False

    def __init__(
        self,
        address: tuple[str, int],
        root: Path,
        runtime_dir: Path | None = None,
        model_config_path: Path | None = None,
    ) -> None:
        host = address[0]
        token = os.getenv("AEGIS_API_TOKEN", "").strip()
        if not _is_loopback_host(host) and not token:
            raise ValueError("非本机监听必须设置 AEGIS_API_TOKEN")
        if model_config_path is not None and not (root / model_config_path).is_file():
            raise ValueError(f"Model configuration not found: {model_config_path}")
        self.api_token = token
        super().__init__(address, AegisHandler)
        self.root = root
        self.web_root = (root / "web").resolve()
        self.service = ConversationService(root, runtime_dir=runtime_dir, model_config_path=model_config_path)
        # One manager per server keeps the nonce replay registry alive across
        # requests while sharing the service's policy and append-only audit.
        self.routing = RoutingManager(self.service)
        self.limiter = RateLimiter()

    def server_close(self) -> None:
        try:
            self.service.close()
        finally:
            super().server_close()


class AegisHandler(BaseHTTPRequestHandler):
    server: AegisServer
    protocol_version = "HTTP/1.1"
    server_version = "AegisGate"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        try:
            path = urlparse(getattr(self, "path", "/")).path or "/"
        except ValueError:
            path = "/"
        safe_path = path.encode("unicode_escape", errors="backslashreplace").decode("ascii")[:512]
        raw_method = str(getattr(self, "command", "-") or "-")
        method = raw_method if raw_method in LOGGABLE_METHODS else "INVALID_METHOD"
        client = str(self.client_address[0]) if self.client_address else "-"
        print(f"[{self.log_date_time_string()}] {client} {method} {safe_path}")

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        try:
            status = HTTPStatus(code)
        except ValueError:
            status = HTTPStatus.BAD_REQUEST
        public_messages = {
            HTTPStatus.BAD_REQUEST: "请求格式无效",
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE: "请求体超过大小限制",
            HTTPStatus.REQUEST_URI_TOO_LONG: "请求目标过长",
            HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE: "请求头无效",
            HTTPStatus.NOT_IMPLEMENTED: "不支持的请求方法",
            HTTPStatus.HTTP_VERSION_NOT_SUPPORTED: "不支持的 HTTP 版本",
        }
        payload = {
            "error": {
                "code": "HTTP_ERROR",
                "message": public_messages.get(status, "请求无法处理"),
            }
        }
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        if getattr(self, "command", "") != "HEAD":
            self.wfile.write(content)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            self._begin_api_request()
        if path.startswith("/api/") and not self._authorize():
            return
        if path == "/api/health":
            self._json(
                {
                    "status": "ok",
                    "service": "AegisGate",
                    "version": "3.1.0",
                    "model": self.server.service.llm.status(),
                    "semantic_model": self.server.service.engine.semantic_model_status(),
                }
            )
            return
        if path == "/api/v1/stats":
            try:
                day = parse_qs(parsed.query).get("date", [None])[-1]
                self._json(self.server.service.stats(day))
            except ValueError:
                self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", "请求参数无效")
        elif path == "/api/v1/observability/metrics":
            try:
                day = parse_qs(parsed.query).get("date", [None])[-1]
                self._json(self.server.service.observability_metrics(day))
            except ValueError:
                self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", "璇锋眰鍙傛暟鏃犳晥")
        elif path == "/api/v1/openapi.json":
            self._json(build_openapi("3.1.0"))
        elif path == "/api/v2/telemetry/routing":
            try:
                scope = self._request_scope()
                if not self._require_permission("read"):
                    return
                params = parse_qs(parsed.query)
                page = int(params.get("page", ["1"])[-1])
                page_size = int(params.get("page_size", ["50"])[-1])
                route = params.get("route", [""])[-1]
                self._json(
                    self.server.service.routing_telemetry(
                        scope=scope, page=page, page_size=page_size, route=route
                    )
                )
            except (RequestValidationError, TelemetryScopeError, ValueError, TypeError):
                self._error(HTTPStatus.BAD_REQUEST, "INVALID_SCOPE", "遥测查询作用域或分页参数无效")
        elif path == "/api/v2/invention/evidence":
            try:
                scope = self._request_scope()
                if not self._require_permission("read"):
                    return
                params = parse_qs(parsed.query)
                page = int(params.get("page", ["1"])[-1])
                page_size = int(params.get("page_size", ["50"])[-1])
                request_id = params.get("request_id", [""])[-1]
                if len(request_id) > 128:
                    raise EvidenceScopeError("request_id 格式无效")
                self._json(
                    self.server.service.invention_evidence_graph(
                        scope=scope,
                        request_id=request_id,
                        page=page,
                        page_size=page_size,
                    )
                )
            except (RequestValidationError, EvidenceScopeError, ValueError, TypeError):
                self._error(HTTPStatus.BAD_REQUEST, "INVALID_SCOPE", "证据查询作用域或分页参数无效")
        elif path == "/api/v1/enterprise" or path.startswith("/api/v1/enterprise/"):
            self._enterprise_get(parsed)
        elif path == "/api/v1/model/status":
            self._json(self.server.service.llm.status())
        elif path == "/api/v1/semantic-model/status":
            self._json(self.server.service.engine.semantic_model_status())
        elif path == "/api/v1/governance/status":
            self._json(self.server.service.governance_status())
        elif path == "/api/v1/ops/overview":
            try:
                scope = self._request_scope()
                if not self._require_permission("read"):
                    return
                self._json(
                    self.server.service.operations_overview(
                        tenant_id=scope["tenant_id"], project_id=scope["project_id"]
                    )
                )
            except RequestValidationError as exc:
                self._error(HTTPStatus.BAD_REQUEST, "INVALID_SCOPE", str(exc))
                return
        elif path == "/api/v1/ops/events/verify":
            if not self._require_permission("read"):
                return
            self._json(self.server.service.operations_verify())
        elif path.startswith("/api/v1/ops/"):
            resource = unquote(path.removeprefix("/api/v1/ops/")).strip("/")
            if "/" in resource or resource in {"overview", "events", ""}:
                self._error(HTTPStatus.NOT_FOUND, "API_NOT_FOUND", "接口不存在")
                return
            try:
                scope = self._request_scope()
                if not self._require_permission("read"):
                    return
                params = parse_qs(parsed.query)
                page = int(params.get("page", ["1"])[-1])
                page_size = int(params.get("page_size", ["50"])[-1])
                result = self.server.service.operations_list(
                    resource,
                    page=page,
                    page_size=page_size,
                    status=params.get("status", [""])[-1],
                    severity=params.get("severity", [""])[-1],
                    query=params.get("q", [""])[-1],
                    tenant_id=scope["tenant_id"],
                    project_id=scope["project_id"],
                )
            except (ValueError, TypeError, RequestValidationError) as exc:
                self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", "运营查询参数无效")
                return
            self._json(result)
        elif path == "/api/v1/policy":
            policy = self.server.service.engine.policy
            _, policy_digest = self.server.routing.policy
            counts = {
                category: len(value.get("terms", []))
                for category, value in self.server.service.engine.keywords.categories().items()
            }
            self._json(
                {
                    "policy_id": policy.data.get("policy_id"),
                    "version": policy.version,
                    "policy_digest": policy_digest,
                    "thresholds": policy.data.get("thresholds", {}),
                    "category_names": policy.data.get("category_names", {}),
                    "keyword_counts": counts,
                    "official_categories": policy.official_categories(),
                }
            )
        elif path == "/api/v1/keywords":
            self._json(self.server.service.engine.keywords.api_payload())
        elif path == "/api/v1/reviews":
            self._json({"items": self.server.service.audit.pending_reviews()})
        elif path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "API_NOT_FOUND", "接口不存在")
        else:
            self._static(path)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "页面不存在")
            return
        self._begin_api_request()
        if not self._authorize():
            return
        if not self.server.limiter.allow(self.client_address[0]):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "RATE_LIMITED", "请求过于频繁")
            return
        try:
            payload = self._read_json()
            if path == "/api/v2/gateway/preflight":
                scope = self._request_scope()
                history = payload.get("history")
                if history is not None and (not isinstance(history, list) or any(not isinstance(item, str) for item in history)):
                    raise RequestValidationError("history 必须是字符串数组")
                result = self.server.routing.preflight_request(
                    text=payload.get("text", ""),
                    history=history,
                    scope=scope,
                    client_capability=str(payload.get("client_capability") or "web-preflight-1"),
                    request_id=payload.get("request_id"),
                    nonce=payload.get("nonce"),
                )
                self._json(result)
            elif path == "/api/v2/gateway/route":
                scope = self._request_scope()
                result = self.server.routing.route_request(payload=payload, scope=scope)
                self._json(result)
            elif path == "/api/v1/enterprise" or path.startswith("/api/v1/enterprise/"):
                self._enterprise_post(path, payload)
            elif path.startswith("/api/v1/ops/"):
                resource = unquote(path.removeprefix("/api/v1/ops/")).strip("/")
                if "/" in resource or resource in {"overview", "events", ""}:
                    self._error(HTTPStatus.NOT_FOUND, "API_NOT_FOUND", "接口不存在")
                    return
                scope = self._request_scope()
                if not self._require_permission("write", resource=resource):
                    return
                created = self.server.service.operations_create(
                    resource,
                    payload,
                    actor=scope["user_id"],
                    scope=scope,
                )
                self._json(created, HTTPStatus.CREATED)
            elif path == "/api/v1/privacy/scan":
                text = payload.get("text", "")
                strategy = payload.get("strategy", "mask")
                if not isinstance(text, str) or not text.strip():
                    raise RequestValidationError("text 必须是非空字符串")
                if not isinstance(strategy, str):
                    raise RequestValidationError("strategy 必须是字符串")
                self._json(self.server.service.privacy_scan(text, strategy))
            elif path == "/api/v1/detect":
                text = payload.get("text", "")
                direction = payload.get("direction", "input")
                self._json(self.server.service.detect(text, direction).to_dict())
            elif path == "/api/v1/sequence":
                scope = self._request_scope()
                decision, analysis = self.server.service.detect_sequence(
                    payload.get("turns", []),
                    payload.get("direction", "input"),
                    session_id=payload.get("session_id"),
                    scope=scope,
                )
                self._json({"decision": decision.to_dict(), "context_analysis": analysis})
            elif path == "/api/v1/batch/detect":
                direction = payload.get("direction", "input")
                records = payload.get("records")
                include_safe_text = payload.get("include_safe_text", False)
                if not isinstance(include_safe_text, bool):
                    raise RequestValidationError("include_safe_text 必须是布尔值")
                self._json(
                    self.server.service.batch_detect(
                        records, direction, include_safe_text=include_safe_text
                    )
                )
            elif path == "/api/v1/chat":
                text = payload.get("input")
                if not isinstance(text, str) or not text.strip():
                    raise RequestValidationError("input 必须是非空字符串")
                history = self._validate_chat_history(payload)
                result = self.server.service.process(
                    text,
                    history,
                    payload.get("mock_output") if "mock_output" in payload else None,
                    session_id=payload.get("session_id"),
                    scope=self._request_scope(),
                )
                self._json(result.to_dict())
            elif path == "/api/v1/audit/verify":
                self._json(self.server.service.audit.verify())
            elif path == "/api/v1/reviews/status":
                audit_hash = payload.get("audit_hash")
                status = payload.get("status")
                if not isinstance(audit_hash, str) or not isinstance(status, str):
                    raise RequestValidationError("audit_hash 和 status 必须是字符串")
                scope = self._request_scope()
                try:
                    updated = self.server.service.audit.update_review_status(
                        audit_hash,
                        status,
                        scope=scope,
                        reviewer_id=scope["user_id"],
                    )
                except ValueError as exc:
                    raise RequestValidationError("复核状态参数无效") from exc
                if not updated:
                    self._error(HTTPStatus.NOT_FOUND, "REVIEW_NOT_FOUND", "复核记录不存在或已被清理")
                    return
                self._json({"updated": True, "items": self.server.service.audit.pending_reviews()})
            elif path == "/api/v1/keywords":
                try:
                    added = self.server.service.engine.keywords.add(
                        payload.get("category", ""), payload.get("term", "")
                    )
                except (ValueError, TypeError) as exc:
                    raise RequestValidationError(self._keyword_error(exc)) from exc
                self._json(
                    {
                        "added": added,
                        "keywords": self.server.service.engine.keywords.api_payload(),
                    },
                    HTTPStatus.CREATED if added else HTTPStatus.OK,
                )
            elif path == "/api/v1/keywords/import":
                try:
                    result = self.server.service.engine.keywords.import_data(
                        payload.get("library")
                    )
                except (ValueError, TypeError) as exc:
                    raise RequestValidationError(self._keyword_error(exc)) from exc
                self._json(
                    {
                        **result,
                        "keywords": self.server.service.engine.keywords.api_payload(),
                    }
                )
            else:
                self._error(HTTPStatus.NOT_FOUND, "API_NOT_FOUND", "接口不存在")
        except RequestValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(exc))
        except OperationsValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(exc))
        except EnterpriseValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_ENTERPRISE_REQUEST", str(exc))
        except EnterpriseConflictError as exc:
            self._error(HTTPStatus.CONFLICT, "ENTERPRISE_CONFLICT", str(exc))
        except EnterpriseNotFoundError as exc:
            self._error(HTTPStatus.NOT_FOUND, "ENTERPRISE_NOT_FOUND", str(exc))
        except RoutingReplayError as exc:
            self._error(HTTPStatus.CONFLICT, exc.code, str(exc))
        except RoutingPolicyError as exc:
            self._error(HTTPStatus.CONFLICT, exc.code, str(exc))
        except RoutingSignatureError as exc:
            self._error(HTTPStatus.BAD_REQUEST, exc.code, str(exc))
        except RoutingError as exc:
            self._error(HTTPStatus.BAD_REQUEST, exc.code, str(exc))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", "请求参数无效")
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "服务处理失败")

    def do_DELETE(self) -> None:  # noqa: N802
        self._begin_api_request()
        if not self._authorize():
            return
        if urlparse(self.path).path != "/api/v1/keywords":
            self._error(HTTPStatus.NOT_FOUND, "API_NOT_FOUND", "接口不存在")
            return
        if not self.server.limiter.allow(self.client_address[0]):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "RATE_LIMITED", "请求过于频繁")
            return
        try:
            payload = self._read_json()
            try:
                removed = self.server.service.engine.keywords.remove(
                    payload.get("category", ""), payload.get("term", "")
                )
            except (ValueError, TypeError) as exc:
                raise RequestValidationError(self._keyword_error(exc)) from exc
            if not removed:
                self._error(
                    HTTPStatus.NOT_FOUND,
                    "KEYWORD_NOT_FOUND",
                    "词条不存在或已被并发修改，词库未修改",
                )
                return
            self._json(
                {
                    "removed": removed,
                    "keywords": self.server.service.engine.keywords.api_payload(),
                }
            )
        except RequestValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(exc))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", "请求参数无效")
        except OSError:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "KEYWORD_PERSISTENCE_FAILED",
                "词库持久化失败，原词库未修改",
            )
        except Exception:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "KEYWORD_DELETE_FAILED",
                "词库删除失败，原词库未修改",
            )

    def do_PATCH(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "NOT_FOUND", "页面不存在")
            return
        self._begin_api_request()
        if not self._authorize():
            return
        if not self.server.limiter.allow(self.client_address[0]):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "RATE_LIMITED", "请求过于频繁")
            return
        try:
            parts = [unquote(part) for part in path.split("/") if part]
            if len(parts) == 5 and parts[:3] == ["api", "v1", "enterprise"]:
                resource, record_id = parts[3], parts[4]
                payload = self._read_json()
                scope = self._request_scope()
                if resource in {"users", "roles", "integrations", "scheduled-jobs"} and not self._require_permission("manage", resource=resource):
                    return
                if not self._require_permission("write", resource=resource):
                    return
                sensitive = resource in {"users", "roles", "integrations", "scheduled-jobs"}
                updated = self.server.service.enterprise.update(
                    resource,
                    record_id,
                    payload,
                    scope=scope,
                    require_confirmation=sensitive,
                )
                self._json(updated)
                return
            if len(parts) != 5 or parts[:3] != ["api", "v1", "ops"]:
                self._error(HTTPStatus.NOT_FOUND, "API_NOT_FOUND", "接口不存在")
                return
            resource, record_id = parts[3], parts[4]
            payload = self._read_json()
            scope = self._request_scope()
            if not self._require_permission("write", resource=resource):
                return
            state = payload.get("state")
            if not isinstance(state, str):
                raise RequestValidationError("state 必须是字符串")
            actor = payload.get("actor", "local-admin")
            if not isinstance(actor, str):
                actor = "local-admin"
            note = payload.get("note", "")
            if not isinstance(note, str):
                raise RequestValidationError("note 必须是字符串")
            updated = self.server.service.operations_update_state(
                resource,
                record_id,
                state,
                actor=scope["user_id"],
                note=note,
                scope=scope,
            )
            if updated is None:
                self._error(HTTPStatus.NOT_FOUND, "RESOURCE_NOT_FOUND", "运营记录不存在")
                return
            self._json(updated)
        except RequestValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(exc))
        except OperationsValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", str(exc))
        except EnterpriseValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_ENTERPRISE_REQUEST", str(exc))
        except EnterpriseConflictError as exc:
            self._error(HTTPStatus.CONFLICT, "ENTERPRISE_CONFLICT", str(exc))
        except EnterpriseNotFoundError as exc:
            self._error(HTTPStatus.NOT_FOUND, "ENTERPRISE_NOT_FOUND", str(exc))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST", "请求参数无效")
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "服务处理失败")

    def _enterprise_get(self, parsed: Any) -> None:
        try:
            if not self._require_permission("read"):
                return
            scope = self._request_scope()
            parts = [unquote(part) for part in parsed.path.split("/") if part]
            params = parse_qs(parsed.query)
            store = self.server.service.enterprise
            if parts == ["api", "v1", "enterprise"]:
                self._json(
                    {
                        "schema_version": "1.0",
                        "name": "AegisGate Enterprise Security Operations API",
                        "resources": sorted(
                            [
                                "assets", "asset-groups", "asset-tags", "discovery-tasks", "alerts", "alert-rules",
                                "scan-tasks", "vulnerabilities", "remediation-orders", "test-projects",
                                "test-cases", "test-records", "incidents", "incident-actions", "incident-links", "forensics-records", "iocs",
                                "baseline-rules", "inspection-tasks", "baseline-findings", "work-orders",
                                "report-templates", "reports", "users", "roles", "notifications",
                                "scheduled-jobs", "allowlist", "integrations",
                            ]
                        ),
                        "privacy": {
                            "raw_payloads": False,
                            "raw_logs": False,
                            "credentials": False,
                            "append_only_audit": True,
                        },
                    }
                )
                return
            if parts == ["api", "v1", "enterprise", "schema"]:
                self._json(store.schema())
                return
            if parts == ["api", "v1", "enterprise", "dashboard"]:
                self._json(store.dashboard(scope=scope))
                return
            if parts == ["api", "v1", "enterprise", "todos"]:
                limit = self._query_integer(params, "limit", 100, minimum=1, maximum=200)
                self._json(store.todos(scope=scope, limit=limit))
                return
            if parts == ["api", "v1", "enterprise", "settings"]:
                if not self._require_permission("manage", resource="settings"):
                    return
                self._json(store.settings(scope=scope))
                return
            if parts == ["api", "v1", "enterprise", "audit", "verify"]:
                self._json(store.verify_audit(scope=scope))
                return
            if parts == ["api", "v1", "enterprise", "audit"]:
                if not self._require_permission("manage", resource="audit"):
                    return
                self._json(
                    store.audit_records(
                        scope=scope,
                        page=self._query_integer(params, "page", 1, minimum=1, maximum=1_000_000),
                        page_size=self._query_integer(params, "page_size", 50, minimum=1, maximum=200),
                        resource_type=params.get("resource_type", [""])[-1],
                    )
                )
                return
            if parts == ["api", "v1", "enterprise", "login-logs"]:
                if not self._require_permission("manage", resource="login-logs"):
                    return
                self._json(
                    store.list_login_logs(
                        scope=scope,
                        page=self._query_integer(params, "page", 1, minimum=1, maximum=1_000_000),
                        page_size=self._query_integer(params, "page_size", 50, minimum=1, maximum=200),
                    )
                )
                return
            if len(parts) == 6 and parts[:4] == ["api", "v1", "enterprise", "reports"] and parts[5] == "export":
                export_format = params.get("format", ["pdf"])[-1].lower()
                content, content_type, filename = store.export_report(parts[4], export_format, scope=scope)
                self._bytes(content, content_type, filename)
                return
            if len(parts) == 5 and parts[:3] == ["api", "v1", "enterprise"] and parts[4] == "export":
                export_format = params.get("format", ["csv"])[-1].lower()
                content, content_type, filename = store.export_collection(parts[3], export_format, scope=scope)
                self._bytes(content, content_type, filename)
                return
            if len(parts) == 5 and parts[:3] == ["api", "v1", "enterprise"]:
                if parts[3] in {"users", "roles", "integrations", "scheduled-jobs"} and not self._require_permission("manage", resource=parts[3]):
                    return
                self._json(store.get_record(parts[3], parts[4], scope=scope))
                return
            if len(parts) == 4 and parts[:3] == ["api", "v1", "enterprise"]:
                if parts[3] in {"users", "roles", "integrations", "scheduled-jobs"} and not self._require_permission("manage", resource=parts[3]):
                    return
                filters = {
                    key: params.get(key, [""])[-1]
                    for key in (
                        "status", "severity", "owner", "department", "group_id", "business_level",
                        "assignee", "source", "category", "report_type", "source_type", "order_type",
                        "enabled", "asset_id", "target_asset_id", "source_id", "project_id_ref",
                    )
                    if key in params
                }
                self._json(
                    store.list_records(
                        parts[3],
                        scope=scope,
                        page=self._query_integer(params, "page", 1, minimum=1, maximum=1_000_000),
                        page_size=self._query_integer(params, "page_size", 50, minimum=1, maximum=200),
                        query=params.get("q", [""])[-1],
                        filters=filters,
                        sort=params.get("sort", ["updated_at"])[-1],
                        order=params.get("order", ["desc"])[-1],
                    )
                )
                return
            self._error(HTTPStatus.NOT_FOUND, "API_NOT_FOUND", "企业运营接口不存在")
        except EnterpriseValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_ENTERPRISE_REQUEST", str(exc))
        except EnterpriseConflictError as exc:
            self._error(HTTPStatus.CONFLICT, "ENTERPRISE_CONFLICT", str(exc))
        except EnterpriseNotFoundError as exc:
            self._error(HTTPStatus.NOT_FOUND, "ENTERPRISE_NOT_FOUND", str(exc))
        except (ValueError, TypeError):
            self._error(HTTPStatus.BAD_REQUEST, "INVALID_ENTERPRISE_REQUEST", "企业运营查询参数无效")
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "ENTERPRISE_INTERNAL_ERROR", "企业运营服务处理失败")

    def _enterprise_post(self, path: str, payload: dict[str, Any]) -> None:
        parts = [unquote(part) for part in path.split("/") if part]
        scope = self._request_scope()
        store = self.server.service.enterprise
        if parts == ["api", "v1", "enterprise", "settings"]:
            if not self._require_permission("manage", resource="settings"):
                return
            self._json(store.update_setting(payload, scope=scope))
            return
        if parts == ["api", "v1", "enterprise", "reports", "generate"]:
            if not self._require_permission("write", resource="reports"):
                return
            self._json(store.generate_report(payload, scope=scope), HTTPStatus.CREATED)
            return
        if len(parts) == 5 and parts[:3] == ["api", "v1", "enterprise"] and parts[4] == "import":
            resource = parts[3]
            if not self._require_permission("write", resource=resource):
                return
            self._json(store.import_payload(resource, payload, scope=scope), HTTPStatus.CREATED)
            return
        if len(parts) == 6 and parts[:4] == ["api", "v1", "enterprise", "assets"] and parts[5] == "tags":
            if not self._require_permission("write", resource="assets"):
                return
            tag_ids = payload.get("tag_ids")
            if not isinstance(tag_ids, list):
                raise EnterpriseValidationError("tag_ids 必须是数组")
            self._json(store.set_asset_tags(parts[4], tag_ids, scope=scope))
            return
        if len(parts) == 6 and parts[:4] == ["api", "v1", "enterprise", "roles"] and parts[5] == "asset-groups":
            if not self._require_permission("manage", resource="roles"):
                return
            if payload.get("confirm") != "CONFIRM":
                raise EnterpriseValidationError("角色资产范围变更需要二次确认")
            group_ids = payload.get("group_ids")
            if not isinstance(group_ids, list):
                raise EnterpriseValidationError("group_ids 必须是数组")
            self._json(store.set_role_asset_groups(parts[4], group_ids, scope=scope))
            return
        if len(parts) == 6 and parts[:4] == ["api", "v1", "enterprise", "discovery-tasks"] and parts[5] == "run":
            if not self._require_permission("write", resource="discovery-tasks"):
                return
            if payload.get("confirm") != "CONFIRM":
                raise EnterpriseValidationError("授权连通性检查需要二次确认")
            self._json(store.run_discovery(parts[4], scope=scope))
            return
        if parts == ["api", "v1", "enterprise", "vulnerabilities", "retest", "batch"]:
            if not self._require_permission("write", resource="vulnerabilities"):
                return
            vulnerability_ids = payload.get("vulnerability_ids")
            if not isinstance(vulnerability_ids, list):
                raise EnterpriseValidationError("vulnerability_ids 必须是数组")
            self._json(store.batch_retest(vulnerability_ids, payload, scope=scope), HTTPStatus.CREATED)
            return
        if len(parts) == 6 and parts[:4] == ["api", "v1", "enterprise", "vulnerabilities"] and parts[5] == "retest":
            if not self._require_permission("write", resource="vulnerabilities"):
                return
            self._json(store.create_retest(parts[4], payload, scope=scope), HTTPStatus.CREATED)
            return
        if len(parts) == 6 and parts[:4] == ["api", "v1", "enterprise", "incidents"] and parts[5] == "actions":
            if not self._require_permission("write", resource="incidents"):
                return
            self._json(store.add_incident_action(parts[4], payload, scope=scope), HTTPStatus.CREATED)
            return
        if len(parts) == 6 and parts[:4] == ["api", "v1", "enterprise", "work-orders"] and parts[5] == "receipts":
            if not self._require_permission("write", resource="work-orders"):
                return
            self._json(store.submit_work_order_receipt(parts[4], payload, scope=scope), HTTPStatus.CREATED)
            return
        if len(parts) == 4 and parts[:3] == ["api", "v1", "enterprise"]:
            resource = parts[3]
            if resource in {"users", "roles", "integrations", "scheduled-jobs"} and not self._require_permission("manage", resource=resource):
                return
            if not self._require_permission("write", resource=resource):
                return
            sensitive = resource in {"users", "roles", "integrations", "scheduled-jobs"}
            if sensitive and payload.get("confirm") != "CONFIRM":
                raise EnterpriseValidationError("敏感操作需要二次确认")
            self._json(store.create(resource, payload, scope=scope), HTTPStatus.CREATED)
            return
        self._error(HTTPStatus.NOT_FOUND, "API_NOT_FOUND", "企业运营接口不存在")

    @staticmethod
    def _query_integer(
        params: dict[str, list[str]],
        name: str,
        default: int,
        *,
        minimum: int,
        maximum: int,
    ) -> int:
        raw = params.get(name, [str(default)])[-1]
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise EnterpriseValidationError(f"{name} 必须是整数") from exc
        if not minimum <= value <= maximum:
            raise EnterpriseValidationError(f"{name} 超出允许范围")
        return value

    def _request_scope(self) -> dict[str, str]:
        principal = getattr(self, "_principal", None) or {}
        values = {
            "tenant_id": self.headers.get("X-Aegis-Tenant", principal.get("tenant_id", "local")),
            "project_id": self.headers.get("X-Aegis-Project", principal.get("project_id", "default")),
            "user_id": self.headers.get("X-Aegis-User", principal.get("user_id", "local-admin")),
        }
        for name, value in values.items():
            normalized = str(value).strip().lower()
            if not _SCOPE_VALUE.fullmatch(normalized):
                raise RequestValidationError(f"{name} 格式无效")
            values[name] = normalized
        values["role_id"] = f"rol_{principal.get('role', 'admin')}"
        return values

    def _legacy_require_permission(self, permission: str, *, resource: str = "") -> bool:
        principal = getattr(self, "_principal", {})
        role = principal.get("role", "admin")
        allowed = ROLE_PERMISSIONS.get(role, set())
        if permission in allowed:
            return True
        if permission == "write" and role == "reviewer" and resource in {"alerts", "incidents", "vulnerabilities"}:
            return True
        self._error(HTTPStatus.FORBIDDEN, "FORBIDDEN", "当前角色无权执行该操作")
        raise RequestValidationError("当前角色无权执行该操作")

    def _require_permission(self, permission: str, *, resource: str = "") -> bool:
        principal = getattr(self, "_principal", {})
        role = principal.get("role", "admin")
        allowed = ROLE_PERMISSIONS.get(role, set())
        if permission in allowed:
            return True
        if permission == "write" and role == "reviewer" and resource in {"alerts", "incidents", "vulnerabilities"}:
            return True
        self._error(HTTPStatus.FORBIDDEN, "FORBIDDEN", "当前角色无权执行该操作")
        return False

    def _authorize(self) -> bool:
        expected = self.server.api_token
        enterprise_request = urlparse(self.path).path.startswith("/api/v1/enterprise")
        if not expected:
            self._principal = {
                "tenant_id": "local",
                "project_id": "default",
                "user_id": "local-admin",
                "role": "admin",
            }
            if enterprise_request:
                self._record_enterprise_login(True, "offline_local_mode")
            return True
        provided = self.headers.get("Authorization", "")
        valid = provided.startswith("Bearer ") and hmac.compare_digest(provided[7:], expected)
        if not valid:
            if enterprise_request:
                self._record_enterprise_login(False, "invalid_access_token")
            self._error(HTTPStatus.UNAUTHORIZED, "UNAUTHORIZED", "需要有效的访问令牌")
            return False
        role = self.headers.get("X-Aegis-Role", "admin").strip().lower()
        if role not in ROLE_PERMISSIONS:
            if enterprise_request:
                self._record_enterprise_login(False, "invalid_role")
            self._error(HTTPStatus.FORBIDDEN, "FORBIDDEN", "角色无效")
            return False
        self._principal = {
            "tenant_id": self.headers.get("X-Aegis-Tenant", "local"),
            "project_id": self.headers.get("X-Aegis-Project", "default"),
            "user_id": self.headers.get("X-Aegis-User", "local-admin"),
            "role": role,
        }
        if enterprise_request:
            self._record_enterprise_login(True, "token_authenticated")
        return True

    def _record_enterprise_login(self, success: bool, reason: str) -> None:
        try:
            principal = getattr(self, "_principal", {})
            scope = {
                "tenant_id": self.headers.get("X-Aegis-Tenant", principal.get("tenant_id", "local")),
                "project_id": self.headers.get("X-Aegis-Project", principal.get("project_id", "default")),
                "user_id": self.headers.get("X-Aegis-User", principal.get("user_id", "local-admin")),
            }
            self.server.service.enterprise.record_login(
                success=success,
                source_ip=str(self.client_address[0]) if self.client_address else "unknown",
                user_agent=self.headers.get("User-Agent", ""),
                scope=scope,
                reason=reason,
            )
        except Exception:
            # Authentication must not fail solely because auxiliary audit storage is unavailable.
            return

    def _begin_api_request(self) -> None:
        """Attach a correlation ID to API responses without logging request content."""
        self._request_id = uuid.uuid4().hex

    def _validate_chat_history(self, payload: dict[str, Any]) -> list[str]:
        if "history" not in payload:
            return []
        history = payload["history"]
        if not isinstance(history, list) or any(not isinstance(item, str) for item in history):
            raise RequestValidationError("history 必须是字符串数组")
        maximum = self.server.service.engine.policy.limit("max_history_turns", 12)
        if len(history) > maximum:
            raise RequestValidationError(f"history 最多允许 {maximum} 轮")
        return history

    @staticmethod
    def _keyword_error(error: Exception) -> str:
        """Return a useful category without echoing attacker-controlled text."""
        message = str(error)
        if "顶层" in message or "categories" in message or "对象" in message or "数组" in message:
            return "词库 JSON 格式校验失败"
        if "类别" in message:
            return "词库类别校验失败"
        if "词条" in message:
            return "词条格式校验失败"
        if "分数" in message:
            return "词库分数校验失败"
        return "词库参数校验失败"

    def _read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        media_type = content_type.partition(";")[0].strip().lower()
        if media_type != "application/json":
            raise RequestValidationError("Content-Type 必须为 application/json")
        length = int(self.headers.get("Content-Length", "0"))
        maximum = self.server.service.engine.policy.limit("max_request_bytes", 24576)
        if urlparse(self.path).path.endswith("/import") and urlparse(self.path).path.startswith("/api/v1/enterprise/"):
            maximum = max(maximum, 210_000)
        if length < 0 or length > maximum:
            raise RequestValidationError("请求体超过大小限制")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(value, dict):
            raise TypeError("JSON 顶层必须是对象")
        return value

    def _static(self, request_path: str) -> None:
        decoded_path = unquote(request_path)
        relative = "index.html" if decoded_path in {"", "/"} else decoded_path.lstrip("/")
        candidate = (self.server.web_root / relative).resolve()
        try:
            candidate.relative_to(self.server.web_root)
        except ValueError:
            self._error(HTTPStatus.FORBIDDEN, "FORBIDDEN", "禁止访问")
            return
        if not candidate.is_file():
            candidate = self.server.web_root / "index.html"
        content = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith("text/") else content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        if urlparse(self.path).path.startswith("/api/"):
            request_id = getattr(self, "_request_id", "")
            if request_id:
                self.send_header("X-Aegis-Request-Id", request_id)
            self.send_header("X-Aegis-Backend", "local-python")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _bytes(self, content: bytes, content_type: str, filename: str) -> None:
        safe_filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", filename)[:160] or "aegisgate-export.bin"
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        request_id = getattr(self, "_request_id", "")
        if request_id:
            self.send_header("X-Aegis-Request-Id", request_id)
        self.send_header("X-Aegis-Backend", "local-python")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{safe_filename}"')
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _error(self, status: HTTPStatus, code: str, message: str) -> None:
        self._json({"error": {"code": code, "message": message}}, status)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        )


def serve(root: Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    server = AegisServer((host, port), root)
    print(f"AegisGate 控制台: http://{host}:{server.server_port}")
    print("按 Ctrl+C 停止服务")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
