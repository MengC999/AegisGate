"""Privacy-safe projections over the append-only audit chain."""

from __future__ import annotations

import json
import hashlib
import hmac
import math
import os
import re
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Mapping


class TelemetryScopeError(ValueError):
    code = "TELEMETRY_SCOPE_INVALID"


def _scope(scope: Mapping[str, str] | None) -> tuple[str, str]:
    value = scope or {}
    tenant = str(value.get("tenant_id", "local")).strip().lower()
    project = str(value.get("project_id", "default")).strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", tenant) or not re.fullmatch(
        r"[a-z][a-z0-9_-]{2,63}", project
    ):
        raise TelemetryScopeError("查询作用域无效")
    return tenant, project


class TelemetryStore:
    """Read-only, content-free telemetry derived from AuditStore JSONL."""

    def __init__(self, audit_store: Any) -> None:
        self.audit_store = audit_store
        self._lock = threading.RLock()
        configured = os.getenv("AEGIS_TELEMETRY_SECRET", "").encode("utf-8")
        self._secret = configured or os.urandom(32)

    def scope_fingerprint(self, scope: Mapping[str, str] | None) -> str:
        tenant, project = _scope(scope)
        material = f"aegis-telemetry-v1\0{tenant}\0{project}".encode("utf-8")
        return hmac.new(self._secret, material, hashlib.sha256).hexdigest()

    def tenant_fingerprint(self, scope: Mapping[str, str] | None) -> str:
        tenant, _ = _scope(scope)
        material = f"aegis-telemetry-tenant-v1\0{tenant}".encode("utf-8")
        return hmac.new(self._secret, material, hashlib.sha256).hexdigest()

    def _records(self, scope: Mapping[str, str] | None) -> list[dict[str, Any]]:
        tenant, project = _scope(scope)
        path: Path = self.audit_store.path
        records: list[dict[str, Any]] = []
        with self._lock:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                lines = []
        for line in lines:
            try:
                item = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(item, dict):
                continue
            item_tenant = str(item.get("tenant_id", "local")).strip().lower()
            item_project = str(item.get("project_id", "default")).strip().lower()
            if item_tenant != tenant or item_project != project:
                continue
            records.append(item)
        return records

    @staticmethod
    def _safe_record(item: Mapping[str, Any]) -> dict[str, Any]:
        route = str(item.get("route", ""))
        action = str(item.get("action", ""))
        risk = item.get("risk_score", 0)
        if isinstance(risk, bool) or not isinstance(risk, (int, float)) or not math.isfinite(float(risk)):
            risk = 0
        return {
            "request_id": str(item.get("request_id", ""))[:128],
            "trace_id": str(item.get("trace_id", ""))[:128],
            "route": route if route in {"local_block", "deep_check", "local_observe"} else "",
            "action": action[:32],
            "risk_score": max(0, min(100, int(risk))),
            "policy_version": str(item.get("policy_version", ""))[:64],
            "feature_version": str(item.get("feature_version", ""))[:64],
            "feature_digest": str(item.get("feature_digest", ""))[:64],
            "audit_digest": str(item.get("entry_hash", ""))[:64],
            "timestamp": str(item.get("timestamp", ""))[:32],
            "reason_code": str(item.get("reason", ""))[:120],
        }

    def routing_snapshot(
        self,
        *,
        scope: Mapping[str, str] | None = None,
        page: int = 1,
        page_size: int = 50,
        route: str = "",
    ) -> dict[str, Any]:
        if page < 1 or page_size < 1 or page_size > 200:
            raise TelemetryScopeError("分页参数无效")
        records = [item for item in self._records(scope) if item.get("event_type") == "gateway_route"]
        if route:
            if route not in {"local_block", "deep_check", "local_observe"}:
                raise TelemetryScopeError("route 参数无效")
            records = [item for item in records if item.get("route") == route]
        safe = [self._safe_record(item) for item in records]
        safe.reverse()
        start = (page - 1) * page_size
        items = safe[start : start + page_size]
        route_counts = Counter(item["route"] for item in safe if item["route"])
        action_counts = Counter(item["action"] for item in safe if item["action"])
        scores = [item["risk_score"] for item in safe]
        scope_fingerprint = self.scope_fingerprint(scope)
        return {
            "schema_version": "1.0",
            "scope": {"tenant_id": _scope(scope)[0], "project_id": _scope(scope)[1]},
            "page": page,
            "page_size": page_size,
            "total": len(safe),
            "route_counts": dict(sorted(route_counts.items())),
            "action_counts": dict(sorted(action_counts.items())),
            "average_risk_score": round(sum(scores) / len(scores), 3) if scores else 0.0,
            "audit_integrity": self.audit_store.verify(),
            "scope_fingerprint": scope_fingerprint,
            "tenant_fingerprint": self.tenant_fingerprint(scope),
            "items": items,
        }


__all__ = ["TelemetryScopeError", "TelemetryStore"]
