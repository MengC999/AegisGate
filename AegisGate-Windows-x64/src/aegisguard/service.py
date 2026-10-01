from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import unicodedata
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from .audit import AuditStore
from .engine import SafetyEngine
from .enterprise import EnterpriseOperationsStore
from .llm import LLMClient, LLMResult
from .normalizer import normalize
from .operations import SecurityOperationsStore
from .types import ConversationResult, Decision, Evidence
from .session_state import SessionRiskStateMachine
from .telemetry import TelemetryStore
from .invention_evidence import InventionEvidenceStore


_AUDIT_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(\bauthorization\b\s*[\"']?\s*[:=]\s*)(?:[\"']?)"
        r"(?:(?:bearer|basic)\s+)?[^\s,;\"'}]+"
    ),
    re.compile(r"(?i)\b(bearer\s+)[^\s,;\"'}]+"),
    re.compile(
        r"(?i)(\b(?:[a-z0-9_]*(?:api[_-]?key|token|secret|password))\b"
        r"\s*[\"']?\s*[:=]\s*)"
        r"(?:[\"']?)[^\s,;\"'}]+"
    ),
    re.compile(
        r"(?i)((?:访问令牌|令牌|私钥|密钥|凭证|cookie)"
        r"\s*[\"']?\s*[:=：]\s*)"
        r"(?:[\"']?)[^\s,;\"'}]+"
    ),
    re.compile(r"(?i)\bsk-[a-z0-9_-]{8,}"),
    re.compile(
        r"(?m)(\b[A-Z][A-Z0-9_]{1,127}\b\s*=\s*)"
        r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\]\r\n]+)"
    ),
    re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    re.compile(r"(?<![\w@])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?!\w)"),
    re.compile(r"(?<!\d)\d{17}[0-9Xx](?![0-9Xx])"),
)

_SUPPORT_SELF_HARM_PATTERN = re.compile(
    r"自杀|轻生|不想活|活不下去|想死|结束生命|伤害自己|割腕",
    re.IGNORECASE,
)
_SUPPORT_HELP_PATTERN = re.compile(
    r"求助|怎么办|不想死|阻止|劝阻|热线|帮助我|帮我|心理咨询|救救我|寻求帮助",
    re.IGNORECASE,
)


class ConversationService:
    def __init__(
        self,
        root: Path,
        llm: LLMClient | None = None,
        runtime_dir: Path | None = None,
        model_config_path: Path | None = None,
    ) -> None:
        self.root = root
        self.engine = SafetyEngine(root)
        if model_config_path is not None:
            model_config_path = root / model_config_path
            if not model_config_path.is_file():
                raise FileNotFoundError(f"Model configuration not found: {model_config_path}")
        self.llm = llm or LLMClient(model_config_path or root / "config" / "api_config.json")
        audit_runtime = runtime_dir or root / "runtime"
        self.audit = AuditStore(audit_runtime)
        self.operations = SecurityOperationsStore(
            root / "data" / "security_operations_demo.json",
            audit_runtime / "security_operations.json",
        )
        self._enterprise_database = audit_runtime / "enterprise_operations.db"
        self._enterprise_seed = root / "data" / "security_operations_demo.json"
        self._enterprise: EnterpriseOperationsStore | None = None
        self._enterprise_lock = threading.Lock()
        self.session_states = SessionRiskStateMachine()
        self.telemetry = TelemetryStore(self.audit)
        self.invention_evidence = InventionEvidenceStore(self.audit)
        self._closed = False

    @property
    def enterprise(self) -> EnterpriseOperationsStore:
        if self._closed:
            raise RuntimeError("service is closed")
        if self._enterprise is None:
            with self._enterprise_lock:
                if self._enterprise is None:
                    self._enterprise = EnterpriseOperationsStore(
                        self._enterprise_database,
                        self._enterprise_seed,
                    )
        return self._enterprise

    def close(self) -> None:
        with self._enterprise_lock:
            self._closed = True
            if self._enterprise is not None:
                self._enterprise.close()
                self._enterprise = None

    def detect(
        self,
        text: str,
        direction: str = "input",
        *,
        scope: Mapping[str, str] | None = None,
    ) -> Decision:
        decision = self._detect_with_support(text, direction)
        self._audit_decision(decision, text, scope=scope)
        return decision

    def detect_sequence(
        self,
        turns: Sequence[str],
        direction: str = "input",
        *,
        session_id: str | None = None,
        scope: Mapping[str, str] | None = None,
    ) -> tuple[Decision, dict[str, object]]:
        decision, analysis = self.engine.detect_sequence(turns, direction)
        decision = self._ensure_support_decision(decision, turns[-1], direction)
        if session_id:
            state = self.update_session_state(
                session_id,
                decision,
                analysis=analysis,
                scope=scope,
            )
            analysis = dict(analysis)
            analysis["session_risk"] = state
        self._audit_decision(decision, turns[-1], analysis, scope=scope)
        return decision, analysis

    def update_session_state(
        self,
        session_id: str,
        decision: Decision | Mapping[str, object],
        *,
        analysis: Mapping[str, object] | None = None,
        preflight: Mapping[str, object] | None = None,
        scope: Mapping[str, str] | None = None,
    ) -> dict[str, object]:
        """Update derived session state and append a source-free audit event."""
        resolved = scope or {}
        state = self.session_states.update(
            session_id,
            decision,
            analysis=analysis,
            preflight=preflight,
            tenant_id=str(resolved.get("tenant_id", "local")),
            project_id=str(resolved.get("project_id", "default")),
        )
        self.audit.append(
            {
                "event_type": "session_risk_state",
                "request_id": getattr(decision, "request_id", "") if not isinstance(decision, Mapping) else "",
                "session_id_digest": hashlib.sha256(str(session_id).encode("utf-8")).hexdigest(),
                "tenant_id": state["tenant_id"],
                "project_id": state["project_id"],
                "status": state["status"],
                "risk_score": state["risk_score"],
                "peak_risk_score": state["peak_risk_score"],
                "risk_vector": state["risk_vector"],
                "state_digest": state["state_digest"],
            }
        )
        return state

    def get_session_state(
        self,
        session_id: str,
        *,
        scope: Mapping[str, str] | None = None,
    ) -> dict[str, object] | None:
        resolved = scope or {}
        return self.session_states.get(
            session_id,
            tenant_id=str(resolved.get("tenant_id", "local")),
            project_id=str(resolved.get("project_id", "default")),
        )

    def routing_telemetry(
        self,
        *,
        scope: Mapping[str, str] | None = None,
        page: int = 1,
        page_size: int = 50,
        route: str = "",
    ) -> dict[str, object]:
        return self.telemetry.routing_snapshot(
            scope=scope, page=page, page_size=page_size, route=route
        )

    def invention_evidence_graph(
        self,
        *,
        scope: Mapping[str, str] | None = None,
        request_id: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, object]:
        return self.invention_evidence.graph(
            scope=scope, request_id=request_id, page=page, page_size=page_size
        )

    def stats(self, day: str | None = None) -> dict[str, object]:
        return self.audit.stats(day)

    def observability_metrics(self, day: str | None = None) -> dict[str, object]:
        stats = self.stats(day)
        return {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "window": stats.get("date", ""),
            "requests_total": stats.get("total_requests", 0),
            "interventions_total": stats.get("interventions", 0),
            "intervention_rate": stats.get("intervention_rate", 0.0),
            "average_latency_ms": stats.get("average_latency_ms", 0.0),
            "p95_latency_ms": stats.get("p95_latency_ms", 0.0),
            "p99_latency_ms": stats.get("p99_latency_ms", 0.0),
            "model_failure_rate": stats.get("model_failure_rate", 0.0),
            "rule_actions": stats.get("actions", {}),
            "audit_integrity": stats.get("audit_integrity", {}),
        }

    def privacy_scan(self, text: str, strategy: str = "mask") -> dict[str, object]:
        """Run the shared detector and return a privacy-minimized DLP result."""
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text must be a non-empty string")
        if strategy not in {"mask", "replace", "hash"}:
            raise ValueError("strategy must be mask, replace or hash")
        decision = self.detect(text, "input")
        sensitive = [
            item
            for item in decision.evidence
            if item.category in {"pii", "fraud"} and item.matched
        ]
        safe_text = decision.safe_text if decision.action in {"pass", "mask"} else ""
        if strategy in {"replace", "hash"} and sensitive:
            safe_text = text
            for item in sorted({entry.matched for entry in sensitive}, key=len, reverse=True):
                replacement = "[REDACTED]"
                if strategy == "hash":
                    replacement = f"[sha256:{hashlib.sha256(item.encode('utf-8')).hexdigest()[:16]}]"
                safe_text = re.sub(re.escape(item), replacement, safe_text, flags=re.IGNORECASE)
        return {
            "schema_version": "1.0",
            "strategy": strategy,
            "action": decision.action,
            "risk_level": decision.risk_level,
            "risk_score": decision.risk_score,
            "categories": decision.categories,
            "matched_types": sorted({item.category for item in sensitive}),
            "match_count": len(sensitive),
            "safe_text": safe_text,
            "trace_digest": decision.explanation.get("trace_digest", ""),
            "policy_version": decision.policy_version,
        }

    def governance_status(self) -> dict[str, object]:
        """Return a privacy-safe capability and provenance snapshot.

        The snapshot is intentionally derived from policy, word-library and
        local model metadata only; it never includes credentials or content.
        """
        policy_bytes = json.dumps(
            self.engine.policy.data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        keyword_bytes = json.dumps(
            self.engine.keywords.data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return {
            "schema_version": "1.0",
            "policy_id": self.engine.policy.data.get("policy_id", ""),
            "policy_version": self.engine.policy.version,
            "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            "keyword_library_sha256": hashlib.sha256(keyword_bytes).hexdigest(),
            "semantic_model": self.engine.semantic_model_status(),
            "model_provider": self.llm.status().get("provider", ""),
            "privacy": {
                "raw_content_persisted": False,
                "audit_content_mode": "sha256_and_decision_metadata",
                "preview_requires_explicit_opt_in": True,
                "review_api_content_free": True,
            },
            "capabilities": [
                "bidirectional_conversation_guard",
                "multi_turn_risk_correlation",
                "batch_governance_detection",
                "multi_source_evidence_fusion",
                "privacy_minimized_hash_chain_audit",
                "human_review_queue",
                "security_operations_inventory",
                "alert_and_incident_workflow",
                "vulnerability_lifecycle_tracking",
                "ioc_evidence_registry",
                "enterprise_asset_and_group_inventory",
                "alert_assignment_and_suppression",
                "authorized_bounded_asset_discovery",
                "vulnerability_remediation_and_retest",
                "security_test_project_and_report_archive",
                "incident_response_timeline",
                "baseline_inspection_and_work_orders",
                "immutable_enterprise_audit_chain",
            ],
        }

    def operations_overview(
        self,
        *,
        tenant_id: str = "local",
        project_id: str = "default",
    ) -> dict[str, object]:
        return self.operations.overview(
            self.stats(), tenant_id=tenant_id, project_id=project_id
        )

    def operations_list(
        self,
        resource: str,
        *,
        page: int = 1,
        page_size: int = 50,
        status: str = "",
        severity: str = "",
        query: str = "",
        tenant_id: str = "local",
        project_id: str = "default",
    ) -> dict[str, object]:
        return self.operations.list_records(
            resource,
            page=page,
            page_size=page_size,
            status=status,
            severity=severity,
            query=query,
            tenant_id=tenant_id,
            project_id=project_id,
        )

    def operations_create(
        self,
        resource: str,
        payload: dict[str, object],
        actor: str = "local-admin",
        scope: dict[str, str] | None = None,
    ) -> dict[str, object]:
        return self.operations.create(resource, payload, actor=actor, scope=scope)

    def operations_update_state(
        self,
        resource: str,
        record_id: str,
        state: str,
        actor: str = "local-admin",
        note: str = "",
        scope: dict[str, str] | None = None,
    ) -> dict[str, object] | None:
        return self.operations.update_state(
            resource, record_id, state, actor=actor, note=note, scope=scope
        )

    def operations_verify(self) -> dict[str, object]:
        return self.operations.verify_events()

    def batch_detect(
        self,
        records: Sequence[object],
        direction: str = "input",
        include_safe_text: bool = False,
    ) -> dict[str, object]:
        """Evaluate bounded records while preserving one shared safety path.

        Each input object must contain ``id`` and ``text``.  Only identifiers
        and decisions are returned; raw input is never copied into the batch
        result unless the caller explicitly requests already-safe text.
        """
        if direction not in {"input", "output"}:
            raise ValueError("direction 必须为 input 或 output")
        if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
            raise TypeError("records 必须是对象数组")
        maximum = self.engine.policy.limit("max_batch_records", 500)
        if len(records) < 1 or len(records) > maximum:
            raise ValueError(f"records 数量必须在 1 到 {maximum} 之间")

        batch_id = uuid.uuid4().hex
        started = time.perf_counter()
        cache: dict[tuple[str, str], Decision] = {}
        items: list[dict[str, object]] = []
        action_counts: Counter[str] = Counter()
        category_counts: Counter[str] = Counter()
        official_counts: Counter[str] = Counter()
        risk_buckets: Counter[str] = Counter()

        for index, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                raise TypeError(f"第 {index} 条记录必须是对象")
            record_id = record.get("id")
            text = record.get("text")
            if not isinstance(record_id, str) or not record_id.strip() or len(record_id) > 128:
                raise ValueError(f"第 {index} 条记录的 id 无效")
            if not isinstance(text, str) or not text.strip():
                raise ValueError(f"第 {index} 条记录的 text 必须是非空字符串")
            key = (direction, text)
            decision = cache.get(key)
            deduplicated = decision is not None
            if decision is None:
                decision = self._detect_with_support(text, direction)
                cache[key] = decision
            # Every source record is auditable, including deduplicated records.
            self._audit_decision(decision, text, {"batch_id": batch_id, "batch_index": index})
            action_counts[decision.action] += 1
            risk_buckets[self._risk_bucket(decision.risk_score)] += 1
            for category in decision.categories:
                category_counts[category] += 1
            for category in decision.official_categories:
                official_counts[category] += 1
            item: dict[str, object] = {
                "id": record_id,
                "action": decision.action,
                "risk_level": decision.risk_level,
                "risk_score": decision.risk_score,
                "categories": decision.categories,
                "official_categories": decision.official_categories,
                "policy_version": decision.policy_version,
                "trace_digest": decision.explanation.get("trace_digest", ""),
                "deduplicated": deduplicated,
            }
            if include_safe_text and decision.action in {"pass", "mask"}:
                item["safe_text"] = decision.safe_text
            items.append(item)

        total = len(items)
        violation_count = sum(value for key, value in action_counts.items() if key != "pass")
        summary = {
            "batch_id": batch_id,
            "total_records": total,
            "unique_texts": len(cache),
            "deduplicated_records": total - len(cache),
            "violation_records": violation_count,
            "intervention_rate": round(violation_count / total, 4),
            "action_counts": dict(sorted(action_counts.items())),
            "category_counts": dict(sorted(category_counts.items())),
            "official_category_counts": dict(sorted(official_counts.items())),
            "risk_buckets": dict(sorted(risk_buckets.items())),
            "average_latency_ms": round(sum(item.latency_ms for item in cache.values()) / max(1, len(cache)), 3),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "policy_version": self.engine.policy.version,
            "trace_digest": hashlib.sha256(
                json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        }
        return {"summary": summary, "items": items}

    @staticmethod
    def _risk_bucket(score: int) -> str:
        if score < 35:
            return "0-34"
        if score < 58:
            return "35-57"
        if score < 82:
            return "58-81"
        return "82-100"

    def process(
        self,
        user_input: str,
        history: Sequence[str] | None = None,
        mock_output: str | None = None,
        *,
        session_id: str | None = None,
        scope: Mapping[str, str] | None = None,
    ) -> ConversationResult:
        started = time.perf_counter()
        request_id = uuid.uuid4().hex
        context_analysis = None
        history_turns = self._validate_history(history)
        filtered_history = self._filter_history(history_turns)
        if filtered_history:
            input_decision, context_analysis = self.engine.detect_sequence(
                [*filtered_history, user_input],
                "input",
                max_turns=len(filtered_history) + 1,
            )
            input_decision = self._ensure_support_decision(input_decision, user_input, "input")
        else:
            input_decision = self._detect_with_support(user_input, "input")
        safe_history = filtered_history
        if input_decision.action not in {"block", "review", "support"}:
            safe_history = self._aggregate_safe_history(filtered_history)
            if safe_history != filtered_history:
                input_decision = self._detect_with_support(user_input, "input")
        if input_decision.action in {"block", "review", "support"}:
            model = self.llm.status()
            action = f"input_{input_decision.action}"
            final = self.engine.policy.data["safe_replies"][input_decision.action]
            result = ConversationResult(
                request_id=request_id,
                action=action,
                final_output=final,
                input_decision=input_decision,
                output_decision=None,
                model_called=False,
                model_provider=model["provider"],
                model_name=model["model_name"],
                model_status="not_called",
                latency_ms=self._elapsed(started),
                context_analysis=context_analysis,
            )
            if session_id:
                state = self.update_session_state(
                    session_id,
                    input_decision,
                    analysis=context_analysis,
                    scope=scope,
                )
                result.context_analysis = dict(context_analysis or {})
                result.context_analysis["session_risk"] = state
            self._audit(result, user_input, "", scope=scope)
            return result

        if mock_output is not None:
            if not self.llm.is_mock_provider():
                raise ValueError("mock_output 仅允许在 provider=mock 时使用")
            model_result = LLMResult(
                mock_output,
                "mock",
                self.llm.status()["model_name"],
                "ok",
                True,
            )
        else:
            model_result = self.llm.chat(input_decision.safe_text, safe_history)
        output_decision = self._detect_with_support(model_result.content, "output")
        model_failed = model_result.status not in {"ok"}
        if model_failed:
            # A provider timeout/unavailability is not a safe pass.  Preserve
            # the provider status for diagnostics while returning the standard
            # safe fallback and moving the session into a blocked state.
            action = "output_block"
            final = self.engine.policy.data["safe_replies"]["output_block"]
        elif output_decision.action == "support":
            action = "output_support"
            final = self.engine.policy.data["safe_replies"]["support"]
        elif output_decision.action in {"block", "review"}:
            action = f"output_{output_decision.action}"
            final = self.engine.policy.data["safe_replies"]["output_block"]
        elif output_decision.action == "mask":
            action = "output_mask"
            final = output_decision.safe_text
        elif input_decision.action == "mask":
            action = "input_mask"
            final = model_result.content
        else:
            action = "pass"
            final = model_result.content
        result = ConversationResult(
            request_id=request_id,
            action=action,
            final_output=final,
            input_decision=input_decision,
            output_decision=output_decision,
            model_called=model_result.request_sent,
            model_provider=model_result.provider,
            model_name=model_result.model_name,
            model_status=model_result.status,
            latency_ms=self._elapsed(started),
            context_analysis=context_analysis,
        )
        if session_id:
            combined_categories = sorted(
                set(result.input_decision.categories)
                | set(result.output_decision.categories if result.output_decision else [])
            )
            combined_score = max(
                result.input_decision.risk_score,
                result.output_decision.risk_score if result.output_decision else 0,
            )
            final_action = result.action
            if result.model_status not in {"ok", "not_called"}:
                final_action = "block"
            state = self.update_session_state(
                session_id,
                {
                    "action": final_action,
                    "risk_score": combined_score,
                    "categories": combined_categories,
                },
                analysis=context_analysis,
                scope=scope,
            )
            result.context_analysis = dict(context_analysis or {})
            result.context_analysis["session_risk"] = state
        self._audit(result, user_input, model_result.content, scope=scope)
        return result

    def _filter_history(self, history: Sequence[str]) -> list[str]:
        safe: list[str] = []
        for item in history:
            decision = self._detect_with_support(item, "input")
            if decision.action in {"pass", "mask"}:
                safe.append(decision.safe_text)
        return safe

    def _aggregate_safe_history(self, history: Sequence[str]) -> list[str]:
        if not history:
            return []
        # Re-check the surviving turns as one combined text. Per-turn
        # filtering alone can miss an injection assembled from individually
        # innocuous fragments.
        # Use a contiguous view as well as the original turns so separators
        # cannot hide a phone number, URL, or split prompt-injection phrase.
        combined_text = "".join(history)
        combined = self._detect_with_support(combined_text, "input")
        # A safety-discussion reducer may lower an explicit prompt-injection
        # finding to ``pass`` for display. That text is still unsafe as model
        # history, so never forward a combined injection even when its action
        # was contextually reduced.
        if any(item.category == "prompt_injection" for item in combined.evidence):
            return []
        if combined.action == "pass":
            return list(history)
        if combined.action == "mask" and combined.safe_text == combined_text:
            return list(history)
        return []

    def _detect_with_support(self, text: str, direction: str) -> Decision:
        decision = self.engine.detect(text, direction)
        return self._ensure_support_decision(decision, text, direction)

    def _ensure_support_decision(
        self,
        decision: Decision,
        text: str,
        direction: str,
    ) -> Decision:
        # A rule-layer block keeps its priority.  Support is a safe care
        # response for a help request, not a way to downgrade an explicit
        # self-harm instruction.
        if decision.action in {"support", "block"} or not self._support_candidate(text):
            return decision
        evidence = Evidence(
            rule_id="support_self_harm_help_seeking",
            source="regex",
            category="self_harm",
            score=0.72,
            description="识别到自伤风险与明确求助意图，进入支持性安全回复",
        )
        return self.engine.detect(
            text,
            direction,
            extra_evidence=[evidence],
            extra_context_flags=["help_seeking"],
        )

    @staticmethod
    def _support_candidate(text: str) -> bool:
        if not isinstance(text, str):
            return False
        normalized = normalize(text)
        views = (text, normalized.canonical, normalized.compact)
        return any(
            _SUPPORT_SELF_HARM_PATTERN.search(view)
            and _SUPPORT_HELP_PATTERN.search(view)
            for view in views
        )

    def _validate_history(self, history: Sequence[str] | None) -> list[str]:
        if history is None:
            return []
        if isinstance(history, (str, bytes)) or not isinstance(history, Sequence):
            raise TypeError("history 必须是字符串数组")
        if any(not isinstance(item, str) for item in history):
            raise TypeError("history 必须是字符串数组")
        maximum = self.engine.policy.limit("max_history_turns", 12)
        if len(history) > maximum:
            raise ValueError(f"history 最多允许 {maximum} 轮")
        return list(history)

    def _audit(
        self,
        result: ConversationResult,
        original_input: str,
        model_output: str,
        *,
        scope: Mapping[str, str] | None = None,
    ) -> None:
        output_categories = result.output_decision.categories if result.output_decision else []
        categories = sorted(set(result.input_decision.categories + output_categories))
        keep_preview = os.getenv("AEGIS_LOG_PREVIEW", "0") == "1"
        record: dict[str, object] = {
                "request_id": result.request_id,
                "action": result.action,
                "categories": categories,
                "official_categories": sorted(
                    set(
                        result.input_decision.official_categories
                        + (
                            result.output_decision.official_categories
                            if result.output_decision else []
                        )
                    )
                ),
                "risk_score": max(
                    result.input_decision.risk_score,
                    result.output_decision.risk_score if result.output_decision else 0,
                ),
                "input_sha256": hashlib.sha256(original_input.encode("utf-8")).hexdigest(),
                "output_sha256": hashlib.sha256(model_output.encode("utf-8")).hexdigest() if model_output else "",
                "input_preview": self._decision_preview(result.input_decision) if keep_preview else "",
                "output_preview": (
                    self._decision_preview(result.output_decision)
                    if keep_preview and result.output_decision else ""
                ),
                "policy_version": result.input_decision.policy_version,
                "latency_ms": round(result.latency_ms, 3),
                "input_trace_digest": result.input_decision.explanation.get("trace_digest", ""),
                "output_trace_digest": (
                    result.output_decision.explanation.get("trace_digest", "")
                    if result.output_decision else ""
                ),
                "history_turns": int((result.context_analysis or {}).get("turn_count", 1)) - 1,
                "temporally_correlated": bool((result.context_analysis or {}).get("correlated", False)),
                "context_trace_digest": (result.context_analysis or {}).get("trace_digest", ""),
            }
        if scope is not None:
            record["tenant_id"] = str(scope.get("tenant_id", "local"))
            record["project_id"] = str(scope.get("project_id", "default"))
        self.audit.append(record)

    def _audit_decision(
        self,
        decision: Decision,
        original_input: str,
        context_analysis: dict[str, object] | None = None,
        *,
        scope: Mapping[str, str] | None = None,
    ) -> None:
        keep_preview = os.getenv("AEGIS_LOG_PREVIEW", "0") == "1"
        record: dict[str, object] = {
                "request_id": uuid.uuid4().hex,
                "action": decision.action,
                "categories": decision.categories,
                "official_categories": decision.official_categories,
                "risk_score": decision.risk_score,
                "input_sha256": hashlib.sha256(original_input.encode("utf-8")).hexdigest(),
                "output_sha256": "",
                "input_preview": self._decision_preview(decision) if keep_preview else "",
                "output_preview": "",
                "policy_version": decision.policy_version,
                "latency_ms": round(decision.latency_ms, 3),
                "input_trace_digest": decision.explanation.get("trace_digest", ""),
                "output_trace_digest": "",
                "history_turns": max(0, int((context_analysis or {}).get("turn_count", 1)) - 1),
                "temporally_correlated": bool((context_analysis or {}).get("correlated", False)),
                "context_trace_digest": (context_analysis or {}).get("trace_digest", ""),
                "direction": decision.direction,
                "batch_id": (context_analysis or {}).get("batch_id", ""),
                "batch_index": (context_analysis or {}).get("batch_index", 0),
            }
        if scope is not None:
            record["tenant_id"] = str(scope.get("tenant_id", "local"))
            record["project_id"] = str(scope.get("project_id", "default"))
        self.audit.append(record)

    @staticmethod
    def _elapsed(started: float) -> float:
        return (time.perf_counter() - started) * 1000

    @classmethod
    def _decision_preview(cls, decision: Decision) -> str:
        """Only a pass or already-masked safe view may enter audit previews."""
        if decision.action not in {"pass", "mask"}:
            return ""
        return cls._audit_preview(decision.safe_text)

    @staticmethod
    def _audit_preview(text: str) -> str:
        # Apply width and all Unicode format-control normalisation before
        # redaction, so PII and credentials cannot bypass it with zero-width or
        # bidirectional lookalikes while ordinary letter casing stays intact.
        sanitized = "".join(
            char
            for char in unicodedata.normalize("NFKC", text)
            if unicodedata.category(char) != "Cf"
        )
        for pattern in _AUDIT_SECRET_PATTERNS:
            sanitized = pattern.sub(
                lambda match: (
                    f"{match.group(1)}[REDACTED]"
                    if match.lastindex and match.group(1)
                    else "[REDACTED]"
                ),
                sanitized,
            )
        return sanitized[:120]
