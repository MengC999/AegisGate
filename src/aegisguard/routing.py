"""Two-level gateway routing with privacy-minimised, replay-resistant tickets.

The browser may provide a preflight *hint*, but the server always recomputes
features when source text is available.  A source-free local block can only
be conservatively blocked; it can never be downgraded to a pass.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from .preflight import FeatureSnapshot, preflight


class RoutingError(ValueError):
    code = "ROUTING_INVALID"
    status = 400


class RoutingReplayError(RoutingError):
    code = "ROUTING_REPLAY"
    status = 409


class RoutingPolicyError(RoutingError):
    code = "ROUTING_POLICY_INVALID"
    status = 409


class RoutingSignatureError(RoutingError):
    code = "ROUTING_SIGNATURE_INVALID"
    status = 400


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _privacy_decision(value: Mapping[str, Any]) -> dict[str, Any]:
    """Strip match values and source offsets from a v2 decision envelope."""
    result = dict(value)
    evidence = result.get("evidence")
    if isinstance(evidence, list):
        safe_items: list[dict[str, Any]] = []
        for item in evidence:
            if not isinstance(item, Mapping):
                continue
            safe = dict(item)
            safe["matched"] = ""
            safe["start"] = -1
            safe["end"] = -1
            safe_items.append(safe)
        result["evidence"] = safe_items
    result.pop("safe_text", None)
    return result


def _feature_categories(feature_ids: Sequence[str]) -> list[str]:
    mapping = {
        "prompt_injection": "prompt_injection",
        "jailbreak": "prompt_injection",
        "privilege_escalation": "prompt_injection",
        "tool_invocation": "prompt_injection",
        "command": "prompt_injection",
        "code": "prompt_injection",
        "data_exfiltration": "pii",
        "credential": "pii",
        "pii": "pii",
    }
    return sorted({mapping[item] for item in feature_ids if item in mapping})


def _now() -> int:
    return int(time.time())


class RoutingManager:
    """Issue and consume short-lived route tickets for one server process."""

    def __init__(self, service: Any, *, ttl_seconds: int = 90, secret: bytes | None = None) -> None:
        self.service = service
        self.ttl_seconds = max(15, min(int(ttl_seconds), 300))
        configured = os.getenv("AEGIS_ROUTING_SECRET", "").encode("utf-8")
        self._secret = secret or configured or os.urandom(32)
        self._used: dict[str, int] = {}
        self._issued: dict[str, int] = {}
        self._lock = threading.RLock()

    @property
    def policy(self) -> tuple[str, str]:
        data = self.service.engine.policy.data
        version = str(data.get("version", "unknown"))
        return version, _digest(data)

    @property
    def model_version(self) -> str:
        try:
            status = self.service.llm.status()
            return str(status.get("model_name") or "unknown")
        except Exception:
            return "unknown"

    def _cleanup(self, now: int) -> None:
        cutoff = now - max(self.ttl_seconds * 2, 300)
        self._used = {key: value for key, value in self._used.items() if value >= cutoff}
        self._issued = {key: value for key, value in self._issued.items() if value >= cutoff}

    @staticmethod
    def _scope(scope: Mapping[str, str] | None) -> dict[str, str]:
        value = scope or {}
        return {
            "tenant_id": str(value.get("tenant_id", "local")),
            "project_id": str(value.get("project_id", "default")),
            "user_id": str(value.get("user_id", "local-admin")),
        }

    def _sign(self, body: Mapping[str, Any]) -> str:
        return hmac.new(self._secret, _canonical(body), hashlib.sha256).hexdigest()

    def _verify_ticket(self, ticket: Any, scope: Mapping[str, str]) -> dict[str, Any]:
        if not isinstance(ticket, Mapping):
            raise RoutingSignatureError("路由票据格式无效")
        body = dict(ticket)
        signature = body.pop("signature", None)
        if not isinstance(signature, str) or not hmac.compare_digest(signature, self._sign(body)):
            raise RoutingSignatureError("路由票据签名无效")
        now = _now()
        try:
            expires_at = int(body["expires_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RoutingError("路由票据过期时间无效") from exc
        if expires_at < now:
            raise RoutingError("路由票据已过期")
        if body.get("tenant_id") != scope["tenant_id"] or body.get("project_id") != scope["project_id"]:
            raise RoutingPolicyError("路由票据作用域不匹配")
        policy_version, policy_digest = self.policy
        if body.get("policy_version") != policy_version or body.get("policy_digest") != policy_digest:
            raise RoutingPolicyError("策略版本或摘要已更新")
        nonce = body.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise RoutingError("路由票据 nonce 无效")
        with self._lock:
            self._cleanup(now)
            if nonce in self._used:
                raise RoutingReplayError("路由票据已被使用")
            self._used[nonce] = now
        return body

    def _ticket(self, snapshot: FeatureSnapshot, scope: Mapping[str, str], trace_id: str) -> dict[str, Any]:
        now = _now()
        body: dict[str, Any] = {
            "request_id": snapshot.request_id,
            "trace_id": trace_id,
            "tenant_id": scope["tenant_id"],
            "project_id": scope["project_id"],
            "policy_version": snapshot.policy_version,
            "policy_digest": snapshot.policy_digest,
            "feature_version": snapshot.feature_version,
            "feature_digest": _digest(snapshot.feature_vector),
            "route": snapshot.route,
            "risk_score": snapshot.risk_score,
            "matched_feature_ids": list(snapshot.matched_feature_ids),
            "nonce": snapshot.nonce,
            "issued_at": now,
            "expires_at": now + self.ttl_seconds,
        }
        body["signature"] = self._sign(body)
        with self._lock:
            self._cleanup(now)
            self._issued[snapshot.nonce] = now
        return body

    def _envelope(
        self,
        *,
        snapshot: FeatureSnapshot,
        scope: Mapping[str, str],
        trace_id: str,
        route: str,
        action: str,
        audit_digest: str,
        reason: str,
        decision: Mapping[str, Any] | None = None,
        feature_digest: str | None = None,
    ) -> dict[str, Any]:
        decision_payload = dict(decision or {})
        if not decision_payload and action in {"block", "review"}:
            category_map = {
                "pii": "pii",
                "prompt_injection": "prompt_injection",
                "jailbreak": "prompt_injection",
                "privilege_escalation": "prompt_injection",
                "data_exfiltration": "pii",
                "credential": "pii",
                "command": "prompt_injection",
                "tool_invocation": "prompt_injection",
            }
            categories = sorted({category_map[item] for item in snapshot.matched_feature_ids if item in category_map})
            level = "critical" if snapshot.risk_score >= 82 else "high" if snapshot.risk_score >= 58 else "medium" if snapshot.risk_score >= 35 else "low"
            decision_payload = {
                "direction": "input",
                "action": action,
                "risk_level": level,
                "risk_score": snapshot.risk_score,
                "categories": categories,
                "official_categories": ["sensitive_speech"] if "prompt_injection" in categories else [],
                "evidence": [
                    {
                        "rule_id": f"preflight_{item}",
                        "source": "preflight",
                        "category": category_map.get(item, "prompt_injection"),
                        "score": round(snapshot.risk_score / 100, 4),
                        "description": f"轻量预过滤特征：{item}",
                    }
                    for item in snapshot.matched_feature_ids
                ],
                "policy_version": snapshot.policy_version,
                "reason": reason,
                "latency_ms": 0.0,
                "context_flags": ["source_free"] if snapshot.client_capability == "source-free-route" else [],
                "explanation": {"trace": [], "graph": {"nodes": []}, "trace_digest": feature_digest or _digest(snapshot.feature_vector)},
                "is_violation": True,
            }
        return {
            "request_id": snapshot.request_id,
            "trace_id": trace_id,
            "tenant_id": scope["tenant_id"],
            "project_id": scope["project_id"],
            "policy_version": snapshot.policy_version,
            "model_version": self.model_version,
            "route": route,
            "risk_score": snapshot.risk_score,
            "action": action,
            "reason": reason,
            "audit_digest": audit_digest,
            "feature_version": snapshot.feature_version,
            "feature_digest": feature_digest or _digest(snapshot.feature_vector),
            "matched_feature_ids": list(snapshot.matched_feature_ids),
            "expires_at": None,
            "decision": decision_payload,
        }

    def _client_snapshot(
        self,
        declaration: Any,
        *,
        request_id: str | None,
    ) -> FeatureSnapshot:
        if not isinstance(declaration, Mapping):
            raise RoutingError("client_preflight 格式无效")
        policy_version, policy_digest = self.policy
        if declaration.get("policy_version") != policy_version or declaration.get("policy_digest") != policy_digest:
            raise RoutingPolicyError("客户端策略版本或摘要已过期")
        route = declaration.get("route")
        if route not in {"local_block", "deep_check", "local_observe"}:
            raise RoutingError("客户端路由声明无效")
        nonce = declaration.get("nonce")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
            raise RoutingError("客户端 nonce 无效")
        try:
            issued_at = int(declaration["issued_at"])
            expires_at = int(declaration["expires_at"])
            risk_score = max(0, min(100, int(declaration["risk_score"])))
        except (KeyError, TypeError, ValueError) as exc:
            raise RoutingError("客户端路由时效或风险分数无效") from exc
        now = _now()
        if issued_at > now + 5 or expires_at < now or expires_at - issued_at > self.ttl_seconds:
            raise RoutingError("客户端路由声明已过期")
        vector = declaration.get("feature_vector")
        if not isinstance(vector, Mapping) or len(vector) > 64:
            raise RoutingError("客户端特征向量无效")
        safe_vector: dict[str, float | int] = {}
        for key, value in vector.items():
            if not isinstance(key, str) or len(key) > 64 or isinstance(value, bool) or not isinstance(value, (int, float)):
                raise RoutingError("客户端特征向量无效")
            safe_vector[key] = value
        matched = declaration.get("matched_feature_ids", [])
        if not isinstance(matched, list) or len(matched) > 64 or any(not isinstance(item, str) or len(item) > 64 for item in matched):
            raise RoutingError("客户端特征标识无效")
        resolved_request_id = request_id or declaration.get("request_id") or uuid.uuid4().hex
        if not isinstance(resolved_request_id, str) or len(resolved_request_id) > 128:
            raise RoutingError("request_id 格式无效")
        with self._lock:
            self._cleanup(now)
            if nonce in self._used:
                raise RoutingReplayError("客户端路由 nonce 已被使用")
            self._used[nonce] = now
        return FeatureSnapshot(
            feature_vector=safe_vector,
            matched_feature_ids=tuple(sorted(set(matched))),
            risk_score=risk_score,
            route=route,
            feature_version=str(declaration.get("feature_version") or "client-preflight-1"),
            policy_version=policy_version,
            policy_digest=policy_digest,
            client_capability=str(declaration.get("client_capability") or "web-preflight-1"),
            nonce=nonce,
            request_id=resolved_request_id,
        )

    def _audit(
        self,
        *,
        snapshot: FeatureSnapshot,
        scope: Mapping[str, str],
        trace_id: str,
        route: str,
        action: str,
        reason: str,
        feature_digest: str | None = None,
        decision: Mapping[str, Any] | None = None,
        conversation: Mapping[str, Any] | None = None,
    ) -> str:
        """Append only safe routing metadata; never include source content."""
        record: dict[str, Any] = {
                "event_type": "gateway_preflight" if action == "preflight" else "gateway_route",
                "request_id": snapshot.request_id,
                "trace_id": trace_id,
                "tenant_id": scope["tenant_id"],
                "project_id": scope["project_id"],
                "route": route,
                "action": action,
                "reason": reason,
                "risk_score": snapshot.risk_score,
                "feature_version": snapshot.feature_version,
                "feature_digest": feature_digest or _digest(snapshot.feature_vector),
                "policy_version": snapshot.policy_version,
                "policy_digest": snapshot.policy_digest,
                "nonce_digest": hashlib.sha256(snapshot.nonce.encode("utf-8")).hexdigest(),
                "matched_feature_ids": list(snapshot.matched_feature_ids),
            }
        if isinstance(decision, Mapping):
            categories = decision.get("categories", [])
            if isinstance(categories, list):
                record["categories"] = [str(item)[:64] for item in categories if isinstance(item, str)][:32]
            explanation = decision.get("explanation")
            if isinstance(explanation, Mapping):
                trace_digest = explanation.get("trace_digest")
                if isinstance(trace_digest, str):
                    record["input_trace_digest"] = trace_digest[:64]
                    record["output_trace_digest"] = trace_digest[:64] if action.startswith("output_") else ""
            model_status = decision.get("model_status")
            if isinstance(model_status, str):
                record["model_status"] = model_status[:32]
            model_version = decision.get("model_version")
            if isinstance(model_version, str):
                record["model_version"] = model_version[:64]
        if isinstance(conversation, Mapping):
            for key in ("model_status", "model_name", "model_provider"):
                value = conversation.get(key)
                if isinstance(value, str):
                    record[key] = value[:64]
            context = conversation.get("context_analysis")
            if isinstance(context, Mapping):
                record["temporally_correlated"] = bool(context.get("correlated", False))
                digest = context.get("trace_digest")
                if isinstance(digest, str):
                    record["context_trace_digest"] = digest[:64]
        return self.service.audit.append(record)

    def preflight_request(
        self,
        *,
        text: str,
        history: Sequence[str] | None = None,
        scope: Mapping[str, str] | None = None,
        client_capability: str = "web-preflight-1",
        request_id: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(text, str) or not text.strip():
            raise RoutingError("text 必须是非空字符串")
        resolved_scope = self._scope(scope)
        policy_version, policy_digest = self.policy
        trace_id = uuid.uuid4().hex
        snapshot = preflight(
            text,
            history=history,
            policy_version=policy_version,
            policy_digest=policy_digest,
            client_capability=client_capability,
            request_id=request_id,
            nonce=nonce,
        )
        ticket = self._ticket(snapshot, resolved_scope, trace_id)
        audit_digest = self._audit(
            snapshot=snapshot,
            scope=resolved_scope,
            trace_id=trace_id,
            route=snapshot.route,
            action="preflight",
            reason="后端生成预过滤摘要和短期路由票据",
        )
        result = self._envelope(
            snapshot=snapshot,
            scope=resolved_scope,
            trace_id=trace_id,
            route=snapshot.route,
            action="preflight",
            audit_digest=audit_digest,
            reason="后端已生成预过滤结果",
        )
        result["ticket"] = ticket
        result["expires_at"] = ticket["expires_at"]
        result["feature_vector"] = dict(snapshot.feature_vector)
        result["policy_digest"] = snapshot.policy_digest
        return result

    def route_request(
        self,
        *,
        payload: Mapping[str, Any],
        scope: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        resolved_scope = self._scope(scope)
        text = payload.get("text")
        history = payload.get("history")
        if history is not None and (not isinstance(history, Sequence) or isinstance(history, (str, bytes))):
            raise RoutingError("history 必须是字符串数组")
        ticket = payload.get("ticket")
        ticket_body: dict[str, Any] | None = None
        client_snapshot: FeatureSnapshot | None = None
        if ticket is not None:
            ticket_body = self._verify_ticket(ticket, resolved_scope)
        if payload.get("client_preflight") is not None:
            if ticket_body is not None:
                raise RoutingError("ticket 与 client_preflight 不能同时提交")
            client_snapshot = self._client_snapshot(
                payload.get("client_preflight"), request_id=payload.get("request_id")
            )
        policy_version, policy_digest = self.policy
        request_id = str((ticket_body or {}).get("request_id") or (client_snapshot.request_id if client_snapshot else None) or payload.get("request_id") or uuid.uuid4().hex)
        nonce = str((ticket_body or {}).get("nonce") or (client_snapshot.nonce if client_snapshot else None) or payload.get("nonce") or uuid.uuid4().hex)
        trace_id = str((ticket_body or {}).get("trace_id") or payload.get("trace_id") or uuid.uuid4().hex)

        if isinstance(text, str) and text.strip():
            snapshot = preflight(
                text,
                history=history,
                policy_version=policy_version,
                policy_digest=policy_digest,
                client_capability=str(payload.get("client_capability") or "web-route-1"),
                request_id=request_id,
                nonce=nonce,
            )
            if ticket_body is not None:
                if ticket_body.get("feature_digest") != _digest(snapshot.feature_vector):
                    audit_digest = self._audit(snapshot=snapshot, scope=resolved_scope, trace_id=trace_id, route="deep_check", action="review", reason="路由特征摘要不一致")
                    return self._envelope(snapshot=snapshot, scope=resolved_scope, trace_id=trace_id, route="deep_check", action="review", audit_digest=audit_digest, reason="路由特征摘要不一致，已进入人工复核")
            # Client hints never lower server risk.  A forged low-risk route
            # is ignored; an over-cautious high-risk hint may only cause a
            # stricter backend route.
            effective_route = snapshot.route
            if client_snapshot is not None and client_snapshot.route == "local_block" and snapshot.route != "local_block":
                effective_route = "deep_check"
            session_state = None
            try:
                mode = str(payload.get("mode") or "detect")
                if mode == "chat":
                    mock_output = payload.get("mock_output") if "mock_output" in payload else None
                    conversation = self.service.process(
                        text,
                        history,
                        mock_output,
                        session_id=payload.get("session_id"),
                        scope=resolved_scope,
                    )
                    selected = conversation.output_decision or conversation.input_decision
                    decision_dict = _privacy_decision(selected.to_dict(include_safe_text=False))
                    action = conversation.action
                    reason = selected.reason or "后端输入检测、模型调用与输出复检完成"
                    # Do not return final_output or raw model content from the
                    # v2 envelope.  v1 retains its established response shape;
                    # v2 exposes only routing and decision metadata by default.
                    conversation_dict: dict[str, Any] | None = {
                        "action": conversation.action,
                        "safe_output": conversation.final_output,
                        "model_called": conversation.model_called,
                        "output_checked": conversation.output_decision is not None,
                        "model_provider": conversation.model_provider,
                        "model_name": conversation.model_name,
                        "model_status": conversation.model_status,
                        "context_analysis": conversation.context_analysis,
                    }
                    if conversation.model_status not in {"ok", "not_called"}:
                        action = "block"
                        reason = "模型不可用或超时，按 fail-closed 处置"
                elif history:
                    decision, context_analysis = self.service.detect_sequence(
                        [*history, text],
                        str(payload.get("direction") or "input"),
                        session_id=payload.get("session_id"),
                        scope=resolved_scope,
                    )
                    decision_dict = _privacy_decision(decision.to_dict(include_safe_text=False))
                    action = decision.action
                    reason = decision.reason or "后端多轮深度检测完成"
                    conversation_dict = {"context_analysis": context_analysis}
                else:
                    decision = self.service.detect(
                        text,
                        str(payload.get("direction") or "input"),
                        scope=resolved_scope,
                    )
                    if payload.get("session_id"):
                        session_state = self.service.update_session_state(
                            str(payload["session_id"]),
                            decision,
                            preflight=snapshot.to_dict(),
                            scope=resolved_scope,
                        )
                    else:
                        session_state = None
                    decision_dict = _privacy_decision(decision.to_dict(include_safe_text=False))
                    action = decision.action
                    reason = decision.reason or "后端深度检测完成"
                    conversation_dict = None
            except Exception:
                action = "block"
                reason = "深度检测异常，按 fail-closed 处置"
                decision_dict = {}
                conversation_dict = None
            audit_digest = self._audit(
                snapshot=snapshot,
                scope=resolved_scope,
                trace_id=trace_id,
                route=effective_route,
                action=action,
                reason=reason,
                decision=decision_dict,
                conversation=conversation_dict,
            )
            result = self._envelope(snapshot=snapshot, scope=resolved_scope, trace_id=trace_id, route=effective_route, action=action, audit_digest=audit_digest, reason=reason, decision=decision_dict)
            if decision_dict:
                result["decision"] = decision_dict
            if conversation_dict is not None:
                result["conversation"] = conversation_dict
            if session_state is None and payload.get("session_id"):
                session_state = self.service.get_session_state(
                    str(payload["session_id"]), scope=resolved_scope
                )
            if session_state is not None:
                result["session_risk"] = session_state
            return result

        if ticket_body is None and client_snapshot is not None:
            trace_id = str(payload.get("trace_id") or uuid.uuid4().hex)
        if ticket_body is None and client_snapshot is None:
            raise RoutingError("缺少 text、有效路由票据或客户端预过滤摘要")
        if client_snapshot is not None:
            if client_snapshot.route == "local_block":
                action, reason, effective_route = "block", "客户端高置信风险摘要，原文未上传，后端保守阻断", "local_block"
            else:
                action, reason, effective_route = "review", "客户端低风险或不确定声明不构成放行依据，按 fail-closed 进入复核", "deep_check"
            audit_digest = self._audit(snapshot=client_snapshot, scope=resolved_scope, trace_id=trace_id, route=effective_route, action=action, reason=reason)
            result = self._envelope(snapshot=client_snapshot, scope=resolved_scope, trace_id=trace_id, route=effective_route, action=action, audit_digest=audit_digest, reason=reason)
            if payload.get("session_id"):
                result["session_risk"] = self.service.update_session_state(
                    str(payload["session_id"]),
                    {"action": action, "risk_score": client_snapshot.risk_score, "categories": _feature_categories(client_snapshot.matched_feature_ids)},
                    preflight=client_snapshot.to_dict(),
                    scope=resolved_scope,
                )
            return result

        assert ticket_body is not None
        declared_route = str(ticket_body.get("route") or "")
        ticket_features = {
            "ticket_risk_score": int(ticket_body.get("risk_score", 0)),
            "ticket_feature_digest": str(ticket_body.get("feature_digest", "")),
        }
        snapshot = FeatureSnapshot(
            feature_vector=ticket_features,
            matched_feature_ids=tuple(str(item) for item in ticket_body.get("matched_feature_ids", []) if isinstance(item, str)),
            risk_score=max(0, min(100, int(ticket_body.get("risk_score", 0)))),
            route=declared_route if declared_route in {"local_block", "deep_check", "local_observe"} else "deep_check",
            feature_version=str(ticket_body.get("feature_version", "unknown")),
            policy_version=policy_version,
            policy_digest=policy_digest,
            client_capability="source-free-route",
            nonce=nonce,
            request_id=request_id,
        )
        feature_digest = str(ticket_body.get("feature_digest", ""))
        if declared_route == "local_block":
            action, reason = "block", "客户端高置信风险摘要，未上传原文，后端保守阻断"
            effective_route = "local_block"
        else:
            action, reason = "review", "缺少原文，无法完成后端深度复核，按 fail-closed 进入复核"
            effective_route = "deep_check"
        audit_digest = self._audit(snapshot=snapshot, scope=resolved_scope, trace_id=trace_id, route=effective_route, action=action, reason=reason, feature_digest=feature_digest)
        result = self._envelope(snapshot=snapshot, scope=resolved_scope, trace_id=trace_id, route=effective_route, action=action, audit_digest=audit_digest, reason=reason, feature_digest=feature_digest)
        if payload.get("session_id"):
            result["session_risk"] = self.service.update_session_state(
                str(payload["session_id"]),
                {"action": action, "risk_score": snapshot.risk_score, "categories": _feature_categories(snapshot.matched_feature_ids)},
                preflight=snapshot.to_dict(),
                scope=resolved_scope,
            )
        return result


__all__ = ["RoutingError", "RoutingReplayError", "RoutingPolicyError", "RoutingSignatureError", "RoutingManager"]
