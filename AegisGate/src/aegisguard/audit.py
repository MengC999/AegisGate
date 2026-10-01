from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import time
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .categories import (
    INTERNAL_TO_OFFICIAL,
    OFFICIAL_CATEGORY_NAMES,
    OFFICIAL_CATEGORY_ORDER,
    to_official_categories,
)


CHINA_TIMEZONE = timezone(timedelta(hours=8), name="Asia/Shanghai")
ACTION_NAMES = ("block", "mask", "review", "pass", "support")
_REQUEST_ID_PATTERN = re.compile(r"[0-9a-f]{32,64}")
_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_AUDIT_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_REVIEW_ACTIONS = frozenset({"review", "input_review", "output_review"})
_REVIEW_STATUSES = frozenset({"pending", "reviewed", "dismissed"})


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditStore:
    """Privacy-minimised audit log with a verifiable SHA-256 hash chain."""

    def __init__(self, runtime_dir: Path) -> None:
        self.runtime_dir = runtime_dir
        self.path = runtime_dir / "audit.jsonl"
        self.review_path = runtime_dir / "review_queue.jsonl"
        self._lock = threading.RLock()
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        try:
            with self.path.open("rb") as handle:
                lines = handle.read().splitlines()
            if not lines:
                return "0" * 64
            return str(json.loads(lines[-1].decode("utf-8")).get("entry_hash", "0" * 64))
        except (OSError, json.JSONDecodeError):
            return "0" * 64

    def append(self, record: dict[str, Any]) -> str:
        with self._lock:
            payload = dict(record)
            payload["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            payload["prev_hash"] = self._last_hash
            digest = hashlib.sha256(_canonical(payload)).hexdigest()
            payload["entry_hash"] = digest
            line = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            self._last_hash = digest
            # Direct detection writes ``review`` while conversation processing
            # uses directional actions.  All three must enter the same queue.
            if record.get("action") in _REVIEW_ACTIONS:
                try:
                    self._append_review(payload)
                except OSError:
                    # The signed audit log is authoritative.  The queue is a
                    # rebuildable review index, so a transient index write
                    # failure must not fail a completed safety decision.
                    pass
            return digest

    def _append_review(self, payload: dict[str, Any]) -> None:
        review = self._safe_review_item(payload)
        if review is None:
            return
        with self.review_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(review, ensure_ascii=False) + "\n")

    def verify(self) -> dict[str, Any]:
        expected_prev = "0" * 64
        total = 0
        if not self.path.exists():
            return {"valid": True, "entries": 0, "message": "审计日志为空"}
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                total += 1
                try:
                    item = json.loads(line)
                    actual = item.pop("entry_hash")
                    if item.get("prev_hash") != expected_prev:
                        return {"valid": False, "entries": total, "line": line_number, "message": "前序哈希不连续"}
                    computed = hashlib.sha256(_canonical(item)).hexdigest()
                    if computed != actual:
                        return {"valid": False, "entries": total, "line": line_number, "message": "条目摘要校验失败"}
                    expected_prev = actual
                except (ValueError, KeyError, json.JSONDecodeError):
                    return {"valid": False, "entries": total, "line": line_number, "message": "日志格式损坏"}
        return {"valid": True, "entries": total, "tail_hash": expected_prev, "message": "哈希链完整"}

    def stats(self, day: str | None = None) -> dict[str, Any]:
        target_date = self._target_date(day)
        actions: Counter[str] = Counter({action: 0 for action in ACTION_NAMES})
        categories: Counter[str] = Counter()
        official_categories: Counter[str] = Counter(
            {category: 0 for category in OFFICIAL_CATEGORY_ORDER}
        )
        total = 0
        total_latency = 0.0
        latencies: list[float] = []
        model_failures = 0
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if self._entry_date(item.get("timestamp")) != target_date:
                        continue
                    # A v2 preflight is a routing hint and must not inflate
                    # enforcement totals or review queues as a safety action.
                    if item.get("event_type") in {"gateway_preflight", "session_risk_state"}:
                        continue
                    total += 1
                    action = self._action_name(item.get("action"))
                    actions[action] += 1
                    if action != "pass":
                        internal = [
                            str(category)
                            for category in item.get("categories", [])
                            if isinstance(category, str)
                        ]
                        categories.update(set(internal))
                        stored_official = item.get("official_categories")
                        if isinstance(stored_official, list):
                            official = [
                                category
                                for category in stored_official
                                if category in OFFICIAL_CATEGORY_ORDER
                            ]
                        else:
                            official = to_official_categories(internal)
                        official_categories.update(set(official))
                    try:
                        latency = float(item.get("latency_ms", 0.0))
                        total_latency += latency
                        if latency >= 0:
                            latencies.append(latency)
                    except (TypeError, ValueError):
                        pass
                    if item.get("model_status") in {"error", "failed", "timeout"}:
                        model_failures += 1
        interventions = total - actions["pass"]
        official_total = sum(official_categories.values())
        return {
            "date": target_date.isoformat(),
            "timezone": "Asia/Shanghai",
            "total_requests": total,
            "violation_requests": interventions,
            "interventions": interventions,
            "intervention_rate": round(interventions / total, 4) if total else 0.0,
            "actions": {action: actions[action] for action in ACTION_NAMES},
            "categories": dict(categories),
            "official_categories": {
                category: {
                    "name": OFFICIAL_CATEGORY_NAMES[category],
                    "count": official_categories[category],
                    "share": (
                        round(official_categories[category] / official_total, 4)
                        if official_total else 0.0
                    ),
                }
                for category in OFFICIAL_CATEGORY_ORDER
            },
            "average_latency_ms": round(total_latency / total, 3) if total else 0.0,
            "p95_latency_ms": self._quantile(latencies, 0.95),
            "p99_latency_ms": self._quantile(latencies, 0.99),
            "model_failure_rate": round(model_failures / total, 4) if total else 0.0,
            "audit_integrity": self.verify(),
        }

    @staticmethod
    def _quantile(values: list[float], quantile: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * quantile)))
        return round(ordered[index], 3)

    @staticmethod
    def _target_date(day: str | None) -> date:
        if day is None or day == "":
            return datetime.now(CHINA_TIMEZONE).date()
        if not isinstance(day, str):
            raise ValueError("date 必须是 YYYY-MM-DD")
        try:
            return date.fromisoformat(day.strip())
        except (TypeError, ValueError):
            raise ValueError("date 必须是 YYYY-MM-DD") from None

    @staticmethod
    def _entry_date(timestamp: Any) -> date | None:
        if not isinstance(timestamp, str):
            return None
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(CHINA_TIMEZONE).date()

    @staticmethod
    def _action_name(action: Any) -> str:
        value = str(action)
        for prefix in ("input_", "output_"):
            if value.startswith(prefix):
                value = value.removeprefix(prefix)
                break
        return value if value in ACTION_NAMES else "review"

    def pending_reviews(self, limit: int = 100) -> list[dict[str, Any]]:
        try:
            requested = int(limit)
        except (TypeError, ValueError):
            requested = 100
        if requested <= 0:
            return []
        requested = min(requested, 1000)
        safe_items: dict[str, dict[str, Any]] = {}
        sequence: list[str] = []

        def collect(item: Any, ordinal: int) -> None:
            review = self._safe_review_item(item)
            if review is None:
                return
            # Malformed legacy rows have no stable hash and remain isolated.
            # The signed audit log is read after the queue and therefore wins
            # whenever both files describe the same review entry.
            key = review["audit_hash"] or f"legacy:{ordinal}"
            if key not in safe_items:
                sequence.append(key)
            safe_items[key] = review

        with self._lock:
            for source in (self.review_path, self.path):
                try:
                    with source.open("r", encoding="utf-8") as handle:
                        for ordinal, line in enumerate(handle):
                            if not line.strip():
                                continue
                            try:
                                item = json.loads(line)
                            except (TypeError, ValueError, json.JSONDecodeError):
                                continue
                            collect(item, ordinal)
                except OSError:
                    continue
        return [safe_items[key] for key in sequence[-requested:]]

    def update_review_status(
        self,
        audit_hash: str,
        status: str,
        *,
        scope: Mapping[str, str] | None = None,
        reviewer_id: str | None = None,
    ) -> bool:
        """Append a review decision without rewriting signed history.

        ``scope`` is optional for v1 callers.  When supplied, the target entry
        must belong to the exact tenant/project pair; a reviewer can therefore
        never acknowledge another scope's queue item by guessing its digest.
        """
        if not isinstance(audit_hash, str) or not _AUDIT_HASH_PATTERN.fullmatch(audit_hash):
            raise ValueError("audit_hash 无效")
        if status not in _REVIEW_STATUSES - {"pending"}:
            raise ValueError("status 必须为 reviewed 或 dismissed")
        target: dict[str, Any] | None = None
        target_scope: dict[str, str] = {"tenant_id": "local", "project_id": "default"}
        requested_scope: dict[str, str] | None = None
        if scope is not None:
            requested_scope = {
                "tenant_id": str(scope.get("tenant_id", "local")).strip().lower(),
                "project_id": str(scope.get("project_id", "default")).strip().lower(),
            }

        # Resolve the immutable source entry directly instead of relying on
        # the rebuildable review index, then enforce the caller's scope.
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if not isinstance(item, dict):
                        continue
                    if item.get("entry_hash") == audit_hash:
                        target = item
                        break
                    if item.get("audit_hash") == audit_hash and target is None:
                        target = item
        except OSError:
            target = None

        if target is not None:
            target_scope = {
                "tenant_id": str(target.get("tenant_id", "local")).strip().lower(),
                "project_id": str(target.get("project_id", "default")).strip().lower(),
            }
            if requested_scope is not None and target_scope != requested_scope:
                return False

        if target is None:
            # Keep the legacy queue fallback for deployments that predate the
            # signed audit file, while still honoring an explicit scope.
            for item in self.pending_reviews(limit=1000):
                if item.get("audit_hash") == audit_hash:
                    target = item
                    break
        if target is None:
            return False
        if requested_scope is not None and target_scope != requested_scope:
            return False
        reviewer_digest = ""
        if isinstance(reviewer_id, str) and reviewer_id.strip():
            reviewer_digest = hashlib.sha256(reviewer_id.strip().lower().encode("utf-8")).hexdigest()
        self.append(
            {
                "event_type": "review_feedback",
                "request_id": target.get("request_id", ""),
                "tenant_id": target_scope["tenant_id"],
                "project_id": target_scope["project_id"],
                "action": "review",
                "categories": target.get("categories", []),
                "official_categories": [
                    to_official_categories([category])[0]
                    for category in target.get("categories", [])
                    if to_official_categories([category])
                ],
                "risk_score": target.get("risk_score", 0),
                "status": status,
                "audit_hash": audit_hash,
                "review_event": True,
                "candidate_evaluation": True,
                "production_policy_changed": False,
                "reviewer_id_digest": reviewer_digest,
            }
        )
        return True

    @staticmethod
    def _safe_review_item(item: Any) -> dict[str, Any] | None:
        """Project only the fixed, non-content review fields for API output."""
        if not isinstance(item, dict):
            return None
        action = item.get("action")
        if action not in _REVIEW_ACTIONS:
            return None
        allowed_categories = set(INTERNAL_TO_OFFICIAL) | set(OFFICIAL_CATEGORY_ORDER)
        categories = item.get("categories", [])
        if not isinstance(categories, list):
            categories = []
        safe_categories = [
            category
            for category in categories
            if isinstance(category, str) and category in allowed_categories
        ]
        risk_score = item.get("risk_score", 0)
        if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
            risk_score = 0
        elif not math.isfinite(risk_score):
            risk_score = 0
        status = item.get("status")
        if status not in _REVIEW_STATUSES:
            status = "pending"
        request_id = item.get("request_id")
        if not isinstance(request_id, str) or not _REQUEST_ID_PATTERN.fullmatch(request_id):
            request_id = ""
        timestamp = item.get("timestamp")
        if not isinstance(timestamp, str) or not _TIMESTAMP_PATTERN.fullmatch(timestamp):
            timestamp = ""
        audit_hash = item.get("audit_hash", item.get("entry_hash"))
        if not isinstance(audit_hash, str) or not _AUDIT_HASH_PATTERN.fullmatch(audit_hash):
            audit_hash = ""
        return {
            "request_id": request_id,
            "timestamp": timestamp,
            "action": action,
            "categories": safe_categories,
            "risk_score": risk_score,
            "audit_hash": audit_hash,
            "status": status,
        }
