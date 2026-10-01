"""Build a privacy-minimised evidence graph from immutable audit entries."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Mapping

from .telemetry import _scope


class EvidenceScopeError(ValueError):
    code = "EVIDENCE_SCOPE_INVALID"


class InventionEvidenceStore:
    """Read-only evidence projections for a tenant/project audit scope.

    The graph deliberately receives no source text.  Its scope fingerprint is
    HMAC-derived so that identical audit entries cannot be correlated across
    tenant projections through a plain hash value.
    """

    _FEATURE_IDS = frozenset(
        {
            "zero_width",
            "invisible_character",
            "homoglyph",
            "script_switch",
            "high_entropy_chunk",
            "abnormal_separator",
            "instruction_density",
            "role_impersonation",
            "prompt_injection",
            "jailbreak",
            "privilege_escalation",
            "tool_invocation",
            "url",
            "command",
            "code",
            "data_exfiltration",
            "credential",
            "pii",
            "fragment_continuity",
        }
    )
    _SAFE_CATEGORIES = frozenset(
        {
            "sexual",
            "violence",
            "fraud",
            "advertising",
            "sensitive_speech",
            "prompt_injection",
            "pii",
            "credential",
            "self_harm",
            "data_exfiltration",
        }
    )

    def __init__(self, audit_store: Any, *, secret: bytes | None = None) -> None:
        self.audit_store = audit_store
        self._lock = threading.RLock()
        configured = os.getenv("AEGIS_EVIDENCE_SECRET", "").encode("utf-8")
        # The process-local fallback is intentionally not persisted.  It keeps
        # offline demonstrations usable without turning a fingerprint secret
        # into a project artifact.
        self._secret = secret or configured or os.urandom(32)

    def scope_fingerprint(self, scope: Mapping[str, str] | None) -> str:
        tenant, project = _scope(scope)
        material = f"aegis-evidence-v1\0{tenant}\0{project}".encode("utf-8")
        return hmac.new(self._secret, material, hashlib.sha256).hexdigest()

    def tenant_fingerprint(self, scope: Mapping[str, str] | None) -> str:
        tenant, _ = _scope(scope)
        material = f"aegis-evidence-tenant-v1\0{tenant}".encode("utf-8")
        return hmac.new(self._secret, material, hashlib.sha256).hexdigest()

    def _records(self, scope: Mapping[str, str] | None) -> list[dict[str, Any]]:
        tenant, project = _scope(scope)
        path: Path = self.audit_store.path
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        records: list[dict[str, Any]] = []
        with self._lock:
            for line in lines:
                try:
                    item = json.loads(line)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(item, dict):
                    continue
                if str(item.get("tenant_id", "local")).strip().lower() != tenant:
                    continue
                if str(item.get("project_id", "default")).strip().lower() != project:
                    continue
                records.append(item)
        return records

    @staticmethod
    def _node(node_id: str, kind: str, label: str, **extra: Any) -> dict[str, Any]:
        value = {"id": node_id[:160], "kind": kind[:40], "label": label[:160]}
        value.update({key: str(item)[:160] for key, item in extra.items() if item is not None})
        return value

    @staticmethod
    def _edge(source: str, target: str, relation: str) -> dict[str, str]:
        return {"from": source[:160], "to": target[:160], "relation": relation[:40]}

    def graph(
        self,
        *,
        scope: Mapping[str, str] | None = None,
        request_id: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        if page < 1 or page_size < 1 or page_size > 200:
            raise EvidenceScopeError("分页参数无效")
        records = self._records(scope)
        if request_id:
            if len(request_id) > 128:
                raise EvidenceScopeError("request_id 格式无效")
            records = [item for item in records if item.get("request_id") == request_id]
        records = [item for item in records if item.get("event_type") in {None, "gateway_route", "session_risk_state"} or item.get("review_event")]
        records.reverse()
        start = (page - 1) * page_size
        selected = records[start : start + page_size]
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, str]] = []

        def add(node: dict[str, Any]) -> None:
            nodes.setdefault(node["id"], node)

        def link(source: str, target: str, relation: str) -> None:
            edge = self._edge(source, target, relation)
            if edge not in edges:
                edges.append(edge)

        for item in selected:
            entry_hash = str(item.get("entry_hash", ""))
            if len(entry_hash) != 64:
                continue
            event_id = f"event:{entry_hash}"
            event_label = "人工复核追加" if item.get("review_event") else "安全判定事件"
            add(self._node(event_id, "event", event_label, timestamp=item.get("timestamp", "")))

            policy_version = str(item.get("policy_version", ""))[:64]
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", policy_version):
                policy_version = ""
            if policy_version:
                policy_id = f"policy:{policy_version}"
                add(self._node(policy_id, "policy", f"策略 {policy_version}"))
                link(policy_id, event_id, "changed_by_policy")

            route = str(item.get("route", ""))
            if route in {"local_block", "deep_check", "local_observe"}:
                route_id = f"route:{route}"
                add(self._node(route_id, "route", route))
                link(route_id, event_id, "triggered_by")

            action = str(item.get("action", ""))
            if action in {"pass", "mask", "review", "block", "support", "input_review", "input_block", "input_mask", "output_review", "output_block", "output_mask"}:
                action_id = f"action:{action}"
                add(self._node(action_id, "final_action", action))
                link(event_id, action_id, "supports")

            categories = item.get("categories", [])
            if isinstance(categories, list):
                for category in sorted(
                    {str(value) for value in categories if isinstance(value, str) and value in self._SAFE_CATEGORIES}
                ):
                    kind = "pii" if category in {"pii", "fraud", "credential"} else "rule"
                    category_id = f"{kind}:{category}"
                    add(self._node(category_id, kind, category))
                    link(category_id, event_id, "supports")

            feature_ids = item.get("matched_feature_ids", [])
            if isinstance(feature_ids, list):
                for feature_id in sorted(
                    {str(value) for value in feature_ids if str(value) in self._FEATURE_IDS}
                ):
                    rule_id = f"rule:preflight:{feature_id}"
                    add(self._node(rule_id, "rule", f"预过滤特征：{feature_id}"))
                    link(rule_id, event_id, "supports")

            if item.get("model_status") or item.get("model_version"):
                model_label = str(item.get("model_version") or item.get("model_name") or "model")
                model_id = f"model:{model_label}"
                add(self._node(model_id, "model", model_label))
                link(model_id, event_id, "supports")
            if item.get("temporally_correlated") or item.get("context_trace_digest"):
                temporal_id = "temporal:session"
                add(self._node(temporal_id, "temporal", "多轮时序关联"))
                link(temporal_id, event_id, "reinforces")
            if item.get("output_trace_digest"):
                output_id = "output_review:shared-pipeline"
                add(self._node(output_id, "output_review", "模型输出二次复检"))
                link(output_id, event_id, "supports")

            if item.get("review_event"):
                review_id = f"human_review:{entry_hash}"
                status = str(item.get("status", "reviewed"))
                add(self._node(review_id, "human_review", f"人工复核：{status}", candidate_eval="true"))
                target_hash = str(item.get("audit_hash", ""))
                target_id = f"event:{target_hash}" if len(target_hash) == 64 else event_id
                link(target_id, review_id, "reviewed_by")
                eval_id = f"candidate_eval:{entry_hash}"
                add(self._node(eval_id, "candidate_evaluation", "候选评测反馈", production_policy_unchanged="true"))
                link(review_id, eval_id, "contradicts" if status == "dismissed" else "reinforces")

        scope_fingerprint = self.scope_fingerprint(scope)
        return {
            "schema_version": "1.0",
            "scope": {"tenant_id": _scope(scope)[0], "project_id": _scope(scope)[1]},
            "page": page,
            "page_size": page_size,
            "total_events": len(records),
            "nodes": list(nodes.values()),
            "edges": edges,
            "audit_integrity": self.audit_store.verify(),
            "scope_fingerprint": scope_fingerprint,
            "tenant_fingerprint": self.tenant_fingerprint(scope),
            "privacy": {
                "raw_content": False,
                "pii_values": False,
                "source_text": False,
            },
        }


__all__ = ["EvidenceScopeError", "InventionEvidenceStore"]
