from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .categories import to_official_categories


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    source: str
    category: str
    score: float
    description: str
    matched: str = ""
    start: int = -1
    end: int = -1

    def to_dict(self) -> dict[str, Any]:
        item = asdict(self)
        item["score"] = round(self.score, 4)
        if self.category in {"pii", "fraud"} and self.matched:
            if len(self.matched) <= 2:
                item["matched"] = "**"
            else:
                item["matched"] = self.matched[:1] + "***" + self.matched[-1:]
        return item


@dataclass
class Decision:
    direction: str
    action: str
    risk_level: str
    risk_score: int
    categories: list[str]
    evidence: list[Evidence]
    safe_text: str
    policy_version: str
    reason: str
    latency_ms: float = 0.0
    context_flags: list[str] = field(default_factory=list)
    explanation: dict[str, Any] = field(default_factory=dict)

    @property
    def is_violation(self) -> bool:
        return self.action != "pass"

    @property
    def official_categories(self) -> list[str]:
        return to_official_categories(self.categories)

    def to_dict(self, include_safe_text: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "direction": self.direction,
            "action": self.action,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "categories": self.categories,
            "official_categories": self.official_categories,
            "evidence": [item.to_dict() for item in self.evidence],
            "policy_version": self.policy_version,
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 3),
            "context_flags": self.context_flags,
            "explanation": self.explanation,
            "is_violation": self.is_violation,
        }
        if include_safe_text:
            result["safe_text"] = self.safe_text
        return result


@dataclass
class ConversationResult:
    request_id: str
    action: str
    final_output: str
    input_decision: Decision
    output_decision: Decision | None
    model_called: bool
    model_provider: str
    model_name: str
    model_status: str
    latency_ms: float
    context_analysis: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "action": self.action,
            "final_output": self.final_output,
            "input_decision": self.input_decision.to_dict(),
            "output_decision": self.output_decision.to_dict() if self.output_decision else None,
            "model_called": self.model_called,
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "model_status": self.model_status,
            "latency_ms": round(self.latency_ms, 3),
            "context_analysis": self.context_analysis,
        }
