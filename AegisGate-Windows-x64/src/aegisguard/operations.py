from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import atomic_save_json, load_json


RESOURCE_NAMES = ("assets", "alerts", "vulnerabilities", "incidents", "iocs")
SEVERITIES = ("critical", "high", "medium", "low", "info")
ASSET_STATUSES = ("online", "offline", "retired")
ALERT_STATUSES = ("open", "investigating", "closed", "false_positive")
VULNERABILITY_STATUSES = ("new", "triaged", "fixing", "retesting", "closed", "accepted")
INCIDENT_STAGES = ("detected", "contained", "eradicated", "recovered", "closed")
IOC_TYPES = ("ip", "domain", "url", "sha256")
DEFAULT_TENANT_ID = "local"
DEFAULT_PROJECT_ID = "default"
DEFAULT_USER_ID = "local-admin"
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{2,63}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", re.I)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.I)
_SAFE_INDICATOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/?=%#@+-]{0,252}")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class OperationsValidationError(ValueError):
    pass


class SecurityOperationsStore:
    """Local SOC data store with bounded fields and append-only change evidence."""

    def __init__(self, seed_path: Path, runtime_path: Path) -> None:
        self.seed_path = seed_path
        self.runtime_path = runtime_path
        self._lock = threading.RLock()
        self._data = self._load()

    def _load(self) -> dict[str, Any]:
        runtime = load_json(self.runtime_path, None)
        if isinstance(runtime, dict):
            return self._normalize_store(runtime, "runtime")
        seed = load_json(self.seed_path, {})
        return self._normalize_store(seed, "demo_seed")

    @staticmethod
    def _normalize_store(value: dict[str, Any], mode: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "1.0",
            "data_mode": mode,
            "events": [],
        }
        for resource in RESOURCE_NAMES:
            items = value.get(resource, [])
            normalized_items = items if isinstance(items, list) else []
            result[resource] = []
            for item in normalized_items:
                if not isinstance(item, dict):
                    continue
                copy = dict(item)
                copy.setdefault("tenant_id", DEFAULT_TENANT_ID)
                copy.setdefault("project_id", DEFAULT_PROJECT_ID)
                copy.setdefault("created_by", "demo-seed")
                if resource == "alerts" and not copy.get("fingerprint"):
                    copy["fingerprint"] = SecurityOperationsStore._alert_fingerprint(copy)
                result[resource].append(copy)
        events = value.get("events", [])
        result["events"] = events if isinstance(events, list) else []
        return result

    def overview(
        self,
        content_stats: dict[str, Any] | None = None,
        *,
        tenant_id: str = DEFAULT_TENANT_ID,
        project_id: str = DEFAULT_PROJECT_ID,
    ) -> dict[str, Any]:
        with self._lock:
            assets = self._scoped_items("assets", tenant_id, project_id)
            alerts = self._scoped_items("alerts", tenant_id, project_id)
            vulnerabilities = self._scoped_items("vulnerabilities", tenant_id, project_id)
            incidents = self._scoped_items("incidents", tenant_id, project_id)
            iocs = self._scoped_items("iocs", tenant_id, project_id)
            severity_counts = {severity: 0 for severity in SEVERITIES}
            for item in alerts:
                severity = item.get("severity", "info")
                if severity in severity_counts:
                    severity_counts[severity] += 1
            return {
                "schema_version": "1.0",
                "generated_at": _now(),
                "data_mode": self._data["data_mode"],
                "scope": {"tenant_id": tenant_id, "project_id": project_id},
                "counts": {
                    "assets": len(assets),
                    "online_assets": sum(item.get("status") == "online" for item in assets),
                    "open_alerts": sum(item.get("status") in {"open", "investigating"} for item in alerts),
                    "critical_alerts": sum(
                        item.get("severity") == "critical" and item.get("status") != "closed"
                        for item in alerts
                    ),
                    "open_vulnerabilities": sum(
                        item.get("status") not in {"closed", "accepted"} for item in vulnerabilities
                    ),
                    "high_risk_vulnerabilities": sum(
                        item.get("severity") in {"critical", "high"}
                        and item.get("status") not in {"closed", "accepted"}
                        for item in vulnerabilities
                    ),
                    "active_incidents": sum(item.get("stage") != "closed" for item in incidents),
                    "iocs": len(iocs),
                },
                "alert_severity": severity_counts,
                "content_safety": content_stats or {},
                "audit_integrity": self.verify_events(),
                "recent_alerts": deepcopy(sorted(alerts, key=lambda item: item.get("updated_at", ""), reverse=True)[:5]),
                "recent_vulnerabilities": deepcopy(
                    sorted(vulnerabilities, key=lambda item: item.get("updated_at", ""), reverse=True)[:5]
                ),
            }

    def list_records(
        self,
        resource: str,
        *,
        page: int = 1,
        page_size: int = 50,
        status: str = "",
        severity: str = "",
        query: str = "",
        tenant_id: str = DEFAULT_TENANT_ID,
        project_id: str = DEFAULT_PROJECT_ID,
    ) -> dict[str, Any]:
        self._resource(resource)
        if page < 1 or page_size < 1 or page_size > 200:
            raise OperationsValidationError("分页参数无效")
        normalized_query = query.strip().casefold()[:100]
        with self._lock:
            items = self._scoped_items(resource, tenant_id, project_id)
        if status:
            items = [item for item in items if item.get("status", item.get("stage")) == status]
        if severity:
            items = [item for item in items if item.get("severity") == severity]
        if normalized_query:
            searchable_fields = {
                "assets": ("name", "address", "owner", "department", "environment"),
                "alerts": ("title", "source", "attack_type", "asset_id"),
                "vulnerabilities": ("title", "cve", "asset_id", "owner"),
                "incidents": ("title", "category", "owner"),
                "iocs": ("value", "type", "source"),
            }[resource]
            items = [
                item
                for item in items
                if any(normalized_query in str(item.get(field, "")).casefold() for field in searchable_fields)
            ]
        items.sort(key=lambda item: item.get("updated_at", item.get("created_at", "")), reverse=True)
        total = len(items)
        offset = (page - 1) * page_size
        return {
            "items": deepcopy(items[offset : offset + page_size]),
            "total": total,
            "page": page,
            "page_size": page_size,
            "data_mode": self._data["data_mode"],
        }

    def create(
        self,
        resource: str,
        payload: dict[str, Any],
        actor: str = DEFAULT_USER_ID,
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self._resource(resource)
        if not isinstance(payload, dict):
            raise OperationsValidationError("请求数据必须是对象")
        with self._lock:
            item = self._validate_create(resource, payload)
            tenant_id, project_id, user_id = self._scope(scope, actor)
            item["tenant_id"] = tenant_id
            item["project_id"] = project_id
            item["created_by"] = user_id
            if resource == "alerts":
                fingerprint = self._alert_fingerprint(item)
                for existing in self._data[resource]:
                    if (
                        existing.get("tenant_id", DEFAULT_TENANT_ID) == tenant_id
                        and existing.get("project_id", DEFAULT_PROJECT_ID) == project_id
                        and existing.get("fingerprint") == fingerprint
                        and existing.get("status") in {"open", "investigating"}
                    ):
                        existing["repeat_count"] = min(
                            1_000_000,
                            int(existing.get("repeat_count", 1)) + int(item.get("repeat_count", 1)),
                        )
                        existing["updated_at"] = _now()
                        self._append_event(
                            "deduplicate",
                            resource,
                            str(existing.get("id", "")),
                            user_id,
                            {"fingerprint": fingerprint, "repeat_count": existing["repeat_count"]},
                            tenant_id=tenant_id,
                            project_id=project_id,
                        )
                        self._persist()
                        response = deepcopy(existing)
                        response["deduplicated"] = True
                        return response
                item["fingerprint"] = fingerprint
            prefix = {
                "assets": "ast",
                "alerts": "alt",
                "vulnerabilities": "vul",
                "incidents": "inc",
                "iocs": "ioc",
            }[resource]
            item["id"] = f"{prefix}_{uuid.uuid4().hex[:12]}"
            item["created_at"] = _now()
            item["updated_at"] = item["created_at"]
            self._data[resource].append(item)
            self._append_event(
                "create",
                resource,
                item["id"],
                user_id,
                {"status": item.get("status", item.get("stage", ""))},
                tenant_id=tenant_id,
                project_id=project_id,
            )
            self._persist()
            return deepcopy(item)

    def update_state(
        self,
        resource: str,
        record_id: str,
        state: str,
        actor: str = "local-admin",
        note: str = "",
        scope: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        self._resource(resource)
        if not isinstance(record_id, str) or not _IDENTIFIER.fullmatch(record_id):
            raise OperationsValidationError("记录 ID 无效")
        if not isinstance(note, str) or len(note) > 500:
            raise OperationsValidationError("处置说明最多 500 个字符")
        allowed = {
            "assets": ASSET_STATUSES,
            "alerts": ALERT_STATUSES,
            "vulnerabilities": VULNERABILITY_STATUSES,
            "incidents": INCIDENT_STAGES,
            "iocs": ("active", "expired", "false_positive"),
        }[resource]
        if state not in allowed:
            raise OperationsValidationError("状态值无效")
        state_field = "stage" if resource == "incidents" else "status"
        with self._lock:
            tenant_id, project_id, user_id = self._scope(scope, actor)
            for item in self._data[resource]:
                if (
                    item.get("id") != record_id
                    or item.get("tenant_id", DEFAULT_TENANT_ID) != tenant_id
                    or item.get("project_id", DEFAULT_PROJECT_ID) != project_id
                ):
                    continue
                previous = item.get(state_field, "")
                item[state_field] = state
                item["updated_at"] = _now()
                self._append_event(
                    "state_change",
                    resource,
                    record_id,
                    user_id,
                    {
                        "from": previous,
                        "to": state,
                        "note_sha256": hashlib.sha256(note.encode("utf-8")).hexdigest() if note else "",
                    },
                    tenant_id=tenant_id,
                    project_id=project_id,
                )
                self._persist()
                return deepcopy(item)
        return None

    def verify_events(self) -> dict[str, Any]:
        expected = "0" * 64
        events = self._data.get("events", [])
        for index, original in enumerate(events, start=1):
            if not isinstance(original, dict):
                return {"valid": False, "entries": index, "message": "事件格式无效"}
            event = dict(original)
            actual = event.pop("event_hash", "")
            if event.get("prev_hash") != expected:
                return {"valid": False, "entries": index, "message": "前序哈希不连续"}
            if hashlib.sha256(_canonical(event)).hexdigest() != actual:
                return {"valid": False, "entries": index, "message": "事件摘要校验失败"}
            expected = actual
        return {"valid": True, "entries": len(events), "tail_hash": expected}

    def _append_event(
        self,
        operation: str,
        resource: str,
        record_id: str,
        actor: str,
        changes: dict[str, Any],
        *,
        tenant_id: str = DEFAULT_TENANT_ID,
        project_id: str = DEFAULT_PROJECT_ID,
    ) -> None:
        events = self._data["events"]
        previous = events[-1].get("event_hash", "0" * 64) if events else "0" * 64
        safe_actor = actor if isinstance(actor, str) and _IDENTIFIER.fullmatch(actor) else "local-admin"
        event = {
            "event_id": uuid.uuid4().hex,
            "timestamp": _now(),
            "operation": operation,
            "resource": resource,
            "record_id": record_id,
            "actor": safe_actor,
            "tenant_id": tenant_id,
            "project_id": project_id,
            "changes": changes,
            "prev_hash": previous,
        }
        event["event_hash"] = hashlib.sha256(_canonical(event)).hexdigest()
        events.append(event)

    def _persist(self) -> None:
        self._data["data_mode"] = "runtime"
        atomic_save_json(self.runtime_path, self._data)

    @staticmethod
    def _resource(resource: str) -> None:
        if resource not in RESOURCE_NAMES:
            raise OperationsValidationError("资源类型无效")

    @staticmethod
    def _scope(scope: dict[str, str] | None, actor: str) -> tuple[str, str, str]:
        values = scope if isinstance(scope, dict) else {}
        tenant_id = str(values.get("tenant_id", DEFAULT_TENANT_ID)).strip().lower()
        project_id = str(values.get("project_id", DEFAULT_PROJECT_ID)).strip().lower()
        user_id = str(values.get("user_id", actor or DEFAULT_USER_ID)).strip().lower()
        for name, value in (("tenant_id", tenant_id), ("project_id", project_id), ("user_id", user_id)):
            if not _IDENTIFIER.fullmatch(value):
                raise OperationsValidationError(f"{name} 格式无效")
        return tenant_id, project_id, user_id

    def _scoped_items(self, resource: str, tenant_id: str, project_id: str) -> list[dict[str, Any]]:
        return [
            item
            for item in self._data[resource]
            if item.get("tenant_id", DEFAULT_TENANT_ID) == tenant_id
            and item.get("project_id", DEFAULT_PROJECT_ID) == project_id
        ]

    @staticmethod
    def _alert_fingerprint(item: dict[str, Any]) -> str:
        basis = {
            "tenant_id": item.get("tenant_id", DEFAULT_TENANT_ID),
            "project_id": item.get("project_id", DEFAULT_PROJECT_ID),
            "source": item.get("source", ""),
            "attack_type": item.get("attack_type", ""),
            "asset_id": item.get("asset_id", ""),
            "source_indicator": item.get("source_indicator", ""),
        }
        return hashlib.sha256(_canonical(basis)).hexdigest()

    def _validate_create(self, resource: str, payload: dict[str, Any]) -> dict[str, Any]:
        if resource == "assets":
            return self._asset(payload)
        if resource == "alerts":
            return self._alert(payload)
        if resource == "vulnerabilities":
            return self._vulnerability(payload)
        if resource == "incidents":
            return self._incident(payload)
        return self._ioc(payload)

    @staticmethod
    def _text(payload: dict[str, Any], key: str, maximum: int, *, required: bool = True) -> str:
        value = payload.get(key, "")
        if not isinstance(value, str):
            raise OperationsValidationError(f"{key} 必须是字符串")
        value = value.strip()
        if required and not value:
            raise OperationsValidationError(f"{key} 不能为空")
        if len(value) > maximum:
            raise OperationsValidationError(f"{key} 最多 {maximum} 个字符")
        return value

    @classmethod
    def _choice(cls, payload: dict[str, Any], key: str, choices: tuple[str, ...], default: str) -> str:
        value = payload.get(key, default)
        if value not in choices:
            raise OperationsValidationError(f"{key} 取值无效")
        return str(value)

    @classmethod
    def _asset(cls, payload: dict[str, Any]) -> dict[str, Any]:
        address = cls._text(payload, "address", 253)
        return {
            "name": cls._text(payload, "name", 120),
            "kind": cls._choice(payload, "kind", ("web", "server", "database", "api", "model", "mobile", "other"), "web"),
            "address": address,
            "environment": cls._choice(payload, "environment", ("production", "staging", "testing", "development"), "production"),
            "importance": cls._choice(payload, "importance", ("core", "high", "normal", "low"), "normal"),
            "status": cls._choice(payload, "status", ASSET_STATUSES, "online"),
            "owner": cls._text(payload, "owner", 80, required=False),
            "department": cls._text(payload, "department", 80, required=False),
            "authorization_scope": cls._text(payload, "authorization_scope", 200, required=False),
        }

    @classmethod
    def _alert(cls, payload: dict[str, Any]) -> dict[str, Any]:
        evidence = cls._text(payload, "evidence", 4000, required=False)
        source_indicator = cls._text(payload, "source_indicator", 253, required=False)
        if source_indicator and (
            not _SAFE_INDICATOR.fullmatch(source_indicator)
            or any(token in source_indicator for token in ("'", '"', "<", ">", "`", ";", "|", "&", "\\n", "\\r"))
        ):
            raise OperationsValidationError("source_indicator contains unsupported payload characters")
        return {
            "title": cls._text(payload, "title", 160),
            "source": cls._text(payload, "source", 80),
            "severity": cls._choice(payload, "severity", SEVERITIES, "medium"),
            "status": cls._choice(payload, "status", ALERT_STATUSES, "open"),
            "attack_type": cls._text(payload, "attack_type", 100, required=False),
            "asset_id": cls._text(payload, "asset_id", 64, required=False),
            "source_indicator": source_indicator,
            "repeat_count": max(1, min(1_000_000, int(payload.get("repeat_count", 1)))),
            "evidence_sha256": hashlib.sha256(evidence.encode("utf-8")).hexdigest() if evidence else "",
            "raw_evidence_persisted": False,
        }

    @classmethod
    def _vulnerability(cls, payload: dict[str, Any]) -> dict[str, Any]:
        cve = cls._text(payload, "cve", 20, required=False).upper()
        if cve and not _CVE.fullmatch(cve):
            raise OperationsValidationError("cve 格式无效")
        cvss_raw = payload.get("cvss", 0)
        if isinstance(cvss_raw, bool) or not isinstance(cvss_raw, (int, float)) or not math.isfinite(cvss_raw):
            raise OperationsValidationError("cvss 必须是 0 到 10 的数值")
        cvss = round(float(cvss_raw), 1)
        if not 0 <= cvss <= 10:
            raise OperationsValidationError("cvss 必须是 0 到 10 的数值")
        return {
            "title": cls._text(payload, "title", 160),
            "cve": cve,
            "cvss": cvss,
            "severity": cls._choice(payload, "severity", SEVERITIES[:-1], "medium"),
            "status": cls._choice(payload, "status", VULNERABILITY_STATUSES, "new"),
            "asset_id": cls._text(payload, "asset_id", 64, required=False),
            "owner": cls._text(payload, "owner", 80, required=False),
            "deadline": cls._text(payload, "deadline", 10, required=False),
            "remediation": cls._text(payload, "remediation", 500, required=False),
            "verification": "not_tested",
        }

    @classmethod
    def _incident(cls, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": cls._text(payload, "title", 160),
            "category": cls._text(payload, "category", 80),
            "severity": cls._choice(payload, "severity", SEVERITIES[:-1], "high"),
            "stage": cls._choice(payload, "stage", INCIDENT_STAGES, "detected"),
            "owner": cls._text(payload, "owner", 80, required=False),
            "impact_scope": cls._text(payload, "impact_scope", 300, required=False),
            "evidence_digest": cls._text(payload, "evidence_digest", 64, required=False),
        }

    @classmethod
    def _ioc(cls, payload: dict[str, Any]) -> dict[str, Any]:
        ioc_type = cls._choice(payload, "type", IOC_TYPES, "ip")
        value = cls._text(payload, "value", 2048)
        valid = False
        if ioc_type == "ip":
            try:
                ipaddress.ip_address(value)
                valid = True
            except ValueError:
                pass
        elif ioc_type == "domain":
            valid = bool(_DOMAIN.fullmatch(value))
        elif ioc_type == "url":
            valid = value.startswith(("http://", "https://")) and len(value) <= 2048
        elif ioc_type == "sha256":
            valid = bool(_SHA256.fullmatch(value))
            value = value.lower()
        if not valid:
            raise OperationsValidationError("IOC 格式与类型不匹配")
        confidence = payload.get("confidence", 50)
        if isinstance(confidence, bool) or not isinstance(confidence, int) or not 0 <= confidence <= 100:
            raise OperationsValidationError("confidence 必须是 0 到 100 的整数")
        return {
            "type": ioc_type,
            "value": value,
            "source": cls._text(payload, "source", 100),
            "confidence": confidence,
            "status": cls._choice(payload, "status", ("active", "expired", "false_positive"), "active"),
            "tags": [
                str(tag).strip()[:40]
                for tag in payload.get("tags", [])[:10]
                if isinstance(tag, str) and str(tag).strip()
            ] if isinstance(payload.get("tags", []), list) else [],
        }
