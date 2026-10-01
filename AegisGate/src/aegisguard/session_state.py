"""Privacy-minimised session risk state machine.

Only derived risk metadata is retained.  Session text, normalized text and
model output are deliberately absent from this module.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping


SESSION_STATUSES = (
    "safe",
    "suspicious",
    "risk_accumulating",
    "high_risk",
    "blocked",
    "review",
    "observing",
    "recovered",
)
_SESSION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def _digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class SessionRiskState:
    session_id: str
    tenant_id: str
    project_id: str
    status: str = "safe"
    risk_score: int = 0
    peak_risk_score: int = 0
    risk_vector: dict[str, float] = field(default_factory=dict)
    turn_count: int = 0
    last_action: str = "pass"
    safe_streak: int = 0
    recovery_required: bool = False
    last_topic_digest: str = ""
    last_updated: float = 0.0
    state_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "project_id": self.project_id,
            "status": self.status,
            "risk_score": self.risk_score,
            "peak_risk_score": self.peak_risk_score,
            "risk_vector": dict(sorted(self.risk_vector.items())),
            "turn_count": self.turn_count,
            "last_action": self.last_action,
            "safe_streak": self.safe_streak,
            "recovery_required": self.recovery_required,
            "last_topic_digest": self.last_topic_digest,
            "updated_at": int(self.last_updated) if self.last_updated else 0,
            "state_digest": self.state_digest,
        }


class SessionRiskStateMachine:
    """Bounded in-memory state machine with decay and monotonic blocking."""

    def __init__(self, *, half_life_seconds: float = 300.0, max_sessions: int = 1000) -> None:
        self.half_life_seconds = max(30.0, float(half_life_seconds))
        self.max_sessions = max(10, int(max_sessions))
        self._states: dict[tuple[str, str, str], SessionRiskState] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate_session_id(value: str) -> str:
        if not isinstance(value, str) or not _SESSION_ID.fullmatch(value):
            raise ValueError("session_id 格式无效")
        return value

    @staticmethod
    def _topic_digest(categories: list[str]) -> str:
        return _digest(sorted(set(categories)) or ["general"])

    @staticmethod
    def _decision_values(decision: Any) -> tuple[str, int, list[str]]:
        if isinstance(decision, Mapping):
            action = str(decision.get("action", "pass"))
            score = int(decision.get("risk_score", 0))
            categories = [str(item) for item in decision.get("categories", []) if isinstance(item, str)]
        else:
            action = str(getattr(decision, "action", "pass"))
            score = int(getattr(decision, "risk_score", 0))
            categories = [str(item) for item in getattr(decision, "categories", []) if isinstance(item, str)]
        for prefix in ("input_", "output_"):
            if action.startswith(prefix):
                action = action.removeprefix(prefix)
                break
        return action, max(0, min(100, score)), categories

    def _prune(self, now: float) -> None:
        if len(self._states) < self.max_sessions:
            return
        stale = sorted(self._states.items(), key=lambda item: item[1].last_updated or 0.0)
        for key, _ in stale[: max(1, len(stale) - self.max_sessions + 1)]:
            self._states.pop(key, None)

    def update(
        self,
        session_id: str,
        decision: Any,
        *,
        analysis: Mapping[str, Any] | None = None,
        preflight: Mapping[str, Any] | None = None,
        tenant_id: str = "local",
        project_id: str = "default",
        now: float | None = None,
    ) -> dict[str, Any]:
        session_id = self._validate_session_id(session_id)
        tenant_id = str(tenant_id)
        project_id = str(project_id)
        current_time = float(time.time() if now is None else now)
        action, current_score, categories = self._decision_values(decision)
        if preflight:
            try:
                current_score = max(current_score, max(0, min(100, int(preflight.get("risk_score", 0)))))
            except (TypeError, ValueError):
                pass
        topic_digest = self._topic_digest(categories)
        key = (tenant_id, project_id, session_id)
        with self._lock:
            self._prune(current_time)
            state = self._states.get(key)
            if state is None:
                state = SessionRiskState(
                    session_id=session_id,
                    tenant_id=tenant_id,
                    project_id=project_id,
                    last_updated=current_time,
                )
                self._states[key] = state
            elapsed = max(0.0, current_time - state.last_updated) if state.turn_count else 0.0
            decay = math.pow(0.5, elapsed / self.half_life_seconds) if elapsed else 1.0
            decayed_previous = state.risk_score * decay
            overlap = bool(set(categories).intersection(state.risk_vector))
            topic_switch = bool(state.last_topic_digest and topic_digest and state.last_topic_digest != topic_digest and not overlap)
            if topic_switch:
                decayed_previous *= 0.5
            reinforcement = min(20.0, decayed_previous * 0.2) if overlap else 0.0
            fragment = bool((analysis or {}).get("correlated"))
            fragment_bonus = 15.0 if any(
                isinstance(item, Mapping) and item.get("mode") == "fragment_assembly"
                for item in (analysis or {}).get("signals", [])
            ) else (10.0 if fragment else 0.0)
            combined_score = max(float(current_score), min(100.0, decayed_previous + reinforcement + fragment_bonus))
            score = int(round(combined_score))
            # Preserve the historical peak even after time decay or a topic switch.
            state.peak_risk_score = max(state.peak_risk_score, score, current_score)
            continuity_factor = 0.5 if topic_switch else 1.0
            for category in list(state.risk_vector):
                state.risk_vector[category] = float(state.risk_vector[category]) * decay * continuity_factor
                if state.risk_vector[category] < 0.001:
                    state.risk_vector.pop(category, None)
            for category in categories:
                state.risk_vector[category] = max(
                    float(state.risk_vector.get(category, 0.0)),
                    current_score / 100.0,
                )
            safe_turn = action == "pass" and current_score < 18 and not fragment
            state.safe_streak = state.safe_streak + 1 if safe_turn else 0
            if action == "block":
                status = "blocked"
                state.recovery_required = True
            elif action == "review":
                status = "review"
                state.recovery_required = True
            elif score >= 82:
                status = "high_risk"
                state.recovery_required = True
            elif state.recovery_required and safe_turn:
                if state.safe_streak >= 3 and score < 35:
                    status = "recovered"
                    state.recovery_required = False
                else:
                    status = "observing"
            elif score >= 35 or reinforcement > 0 or fragment:
                status = "risk_accumulating"
            elif score >= 18:
                status = "suspicious"
            elif state.status == "recovered":
                status = "safe"
            else:
                status = "safe"
            state.status = status
            state.risk_score = score
            state.turn_count += 1
            state.last_action = action
            state.last_topic_digest = topic_digest or state.last_topic_digest
            state.last_updated = current_time
            state.state_digest = _digest({
                "session_id": state.session_id,
                "tenant_id": state.tenant_id,
                "project_id": state.project_id,
                "status": state.status,
                "risk_score": state.risk_score,
                "peak_risk_score": state.peak_risk_score,
                "risk_vector": state.risk_vector,
                "turn_count": state.turn_count,
                "last_action": state.last_action,
                "safe_streak": state.safe_streak,
                "recovery_required": state.recovery_required,
                "last_topic_digest": state.last_topic_digest,
            })
            result = state.to_dict()
            result.update({
                "decayed_previous_score": round(decayed_previous, 3),
                "reinforcement_score": round(reinforcement, 3),
                "fragment_bonus": round(fragment_bonus, 3),
                "topic_switch": topic_switch,
                "historical_peak_preserved": True,
            })
            return result

    def get(self, session_id: str, *, tenant_id: str = "local", project_id: str = "default") -> dict[str, Any] | None:
        session_id = self._validate_session_id(session_id)
        with self._lock:
            state = self._states.get((str(tenant_id), str(project_id), session_id))
            return state.to_dict() if state else None

    def recover(
        self,
        session_id: str,
        *,
        tenant_id: str = "local",
        project_id: str = "default",
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Explicitly mark a blocked/review session as recovered/observing."""
        session_id = self._validate_session_id(session_id)
        with self._lock:
            state = self._states.get((str(tenant_id), str(project_id), session_id))
            if state is None:
                return None
            if state.status in {"blocked", "review", "high_risk", "observing"}:
                state.status = "recovered"
                state.last_action = "recovery"
                state.safe_streak = 3
                state.recovery_required = False
                state.risk_score = 0
                state.risk_vector = {}
                state.last_updated = float(time.time() if now is None else now)
                state.state_digest = _digest({"state": state.to_dict(), "event": "recovery"})
            return state.to_dict()


__all__ = ["SESSION_STATUSES", "SessionRiskState", "SessionRiskStateMachine"]
