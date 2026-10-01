from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

from .categories import INTERNAL_TO_OFFICIAL, to_official_categories
from .classifier import NaiveBayesClassifier
from .normalizer import flexible_term_pattern, mask_value, normalize
from .onnx_classifier import PretrainedONNXClassifier
from .policy import KeywordLibrary, SafetyPolicy, compile_rule
from .types import Decision, Evidence


SAFETY_CONTEXT = re.compile(
    r"为什么不能|如何防范|如何识别|安全研究|安全测试|风险分析|合规审查|新闻报道|"
    r"科普|检测规则|审核这段|识别违规|防止泄露|保护隐私|"
    r"(?:分析|讨论|说明|解释|总结|讲解|审核|检查|识别|检测|分类).{0,36}"
    r"(?:引用|引述|示例|风险|危害|高风险|防护|预防|避险|求助|拒绝理由|检测依据|"
    r"营销内容|广告导流|最小化原则|提示注入|违规|有害|危险)",
    re.IGNORECASE,
)
META_REVIEW_CONTEXT = re.compile(
    r"(?:请|帮忙|需要|用于|为了|应当?).{0,12}"
    r"(?:审核|检查|评估|识别|检测|分类|拦截|拒绝).{0,20}"
    r"(?:内容|文本|话术|广告|色情|暴力|风险|违规|有害)|"
    r"(?:说明|解释).{0,12}(?:为何|为什么).{0,20}(?:违规|有害|危险|高风险|风险)|"
    r"(?:新闻|课堂|培训|政策|合规|防御|反诈).{0,20}(?:讨论|引用|分析|示例|材料)",
    re.IGNORECASE,
)
INSTRUCTION_INTENT = re.compile(r"具体步骤|详细方法|怎么做|如何制作|教我|给出代码|直接执行", re.IGNORECASE)
ACTION_INTENT = re.compile(
    r"可执行(?:细节|步骤|方案|代码)|实际(?:使用|执行|实施|操作)|"
    r"准备(?:实施|执行|发布|传播|投放|攻击|伤害)|"
    r"(?:立即|马上)(?:实施|执行|发布|传播|攻击)|"
    r"帮我(?:实施|执行|发布|传播|攻击)|用于(?:实施|攻击|绕过)",
    re.IGNORECASE,
)
NEGATED_SAFETY_CONTEXT = re.compile(
    r"(?:不是|并非|不属于|无关|别当作|不要当作).{0,10}"
    r"(?:安全研究|安全测试|风险分析|合规审查|新闻报道|科普|安全讨论)|"
    r"(?:安全研究|安全测试|风险分析|合规审查|新闻报道|科普|安全讨论)"
    r".{0,10}(?:只是借口|是幌子|并不安全)",
    re.IGNORECASE,
)
HELP_SEEKING = re.compile(r"求助|怎么办|不想死|阻止|劝阻|热线|帮助我|心理咨询", re.IGNORECASE)
QUOTED_REVIEW = re.compile(r"[“\"].{1,200}[”\"].{0,12}(?:分析|检测|审核|分类)", re.IGNORECASE)
TEMPORAL_CATEGORIES = {
    "sexual", "violence", "sensitive_speech", "self_harm", "illegal", "hate", "fraud", "pii", "prompt_injection", "misinformation"
}
TEMPORAL_FLOORS = {
    "prompt_injection": 0.86,
    "violence": 0.84,
    "sexual": 0.82,
    "sensitive_speech": 0.76,
    "illegal": 0.80,
    "hate": 0.76,
    "fraud": 0.70,
    "pii": 0.82,
    "misinformation": 0.65,
    "self_harm": 0.72,
}
SOURCE_NAMES = {
    "boundary": "边界校验",
    "keyword": "热更新词库",
    "regex": "正则策略",
    "naive_bayes": "朴素贝叶斯辅助信号",
    "pretrained_onnx": "开源预训练 ONNX 模型",
    "temporal": "多轮时序关联",
}


class SafetyEngine:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.policy = SafetyPolicy(root / "config" / "safety_policy.json")
        self.keywords = KeywordLibrary(root / "data" / "keyword_library_v2.json")
        self.classifier = NaiveBayesClassifier(root / "models" / "safety_classifier_v2.json")
        self.pretrained_classifier = PretrainedONNXClassifier(root / "models" / "official_four_onnx_v2")

    def detect(
        self,
        text: str,
        direction: str = "input",
        extra_evidence: Iterable[Evidence] | None = None,
        extra_context_flags: Iterable[str] | None = None,
    ) -> Decision:
        started = time.perf_counter()
        if direction not in {"input", "output"}:
            raise ValueError("direction 必须为 input 或 output")
        if not isinstance(text, str):
            raise TypeError("text 必须是字符串")

        max_chars = self.policy.limit("max_text_chars", 8000)
        if len(text) > max_chars:
            evidence = [Evidence("limit_text", "boundary", "illegal", 1.0, "文本超过安全长度限制")]
            return self._decision(text, direction, evidence, [], started)

        evidence = list(self._keyword_evidence(text))
        evidence.extend(self._regex_evidence(text))
        # Evaluate context before semantic inference as well as afterwards.
        # This prevents an explicit execution request wrapped in a safety
        # disclaimer from being calibrated as benign merely because the
        # disclaimer appears before the model evidence is available.
        preliminary_flags = self._context_flags(text, evidence)
        evidence.extend(self._semantic_evidence(text, evidence, preliminary_flags))
        if extra_evidence:
            evidence.extend(extra_evidence)
        flags = self._context_flags(text, evidence)
        for flag in preliminary_flags:
            if flag not in flags:
                flags.append(flag)
        if extra_context_flags:
            flags.extend(flag for flag in extra_context_flags if flag not in flags)
        return self._decision(text, direction, evidence, flags, started)

    def detect_sequence(
        self,
        turns: Sequence[str],
        direction: str = "input",
        max_turns: int | None = None,
    ) -> tuple[Decision, dict[str, Any]]:
        """Correlate recent turns without persisting their raw text."""
        if direction not in {"input", "output"}:
            raise ValueError("direction 必须为 input 或 output")
        if not isinstance(turns, Sequence) or isinstance(turns, (str, bytes)):
            raise TypeError("turns 必须为字符串数组")
        if any(not isinstance(item, str) for item in turns):
            raise TypeError("turns 中的每一项都必须是字符串")
        maximum = (
            self.policy.limit("max_history_turns", 12)
            if max_turns is None
            else max_turns
        )
        if maximum < 1:
            raise ValueError("max_turns 必须大于 0")
        recent = [item for item in turns[-maximum:] if item.strip()]
        if not recent:
            raise ValueError("turns 不能为空")

        per_turn = [self.detect(item, direction) for item in recent]
        current = per_turn[-1]
        combined_text = "".join(normalize(item).compact for item in recent)
        combined = self.detect(combined_text, direction)
        prior_combined = self.detect(
            "".join(normalize(item).compact for item in recent[:-1]), direction
        ) if len(recent) > 1 else None
        signals: list[dict[str, Any]] = []
        temporal_evidence: list[Evidence] = []

        for category in TEMPORAL_CATEGORIES:
            individual_indexes = [
                index
                for index, decision in enumerate(per_turn)
                if self._has_explicit_evidence(decision, category)
            ]
            combined_explicit = self._has_explicit_evidence(combined, category)
            prior_explicit = bool(
                prior_combined and self._has_explicit_evidence(prior_combined, category)
            )
            fragmented = (
                combined_explicit
                and combined.action != "pass"
                and not individual_indexes
                and not prior_explicit
            )
            current_explicit = self._has_explicit_evidence(current, category)
            previous_indexes = [index for index in individual_indexes if index < len(recent) - 1]
            reinforced = current_explicit and bool(previous_indexes)
            if not fragmented and not reinforced:
                continue

            if fragmented:
                score = max(combined.risk_score / 100.0, TEMPORAL_FLOORS.get(category, 0.72))
                mode = "fragment_assembly"
                indexes = list(range(len(recent)))
                description = "跨轮片段组合后形成完整风险语义"
            else:
                current_peak = max(
                    (item.score for item in current.evidence if item.category == category),
                    default=current.risk_score / 100.0,
                )
                score = min(0.96, max(current_peak, TEMPORAL_FLOORS.get(category, 0.72)) + 0.08 * min(3, len(previous_indexes)))
                mode = "risk_reinforcement"
                indexes = previous_indexes + [len(recent) - 1]
                description = "同类风险在相邻轮次重复出现并被强化"

            temporal_evidence.append(
                Evidence(
                    rule_id=f"temporal_{mode}_{category}",
                    source="temporal",
                    category=category,
                    score=score,
                    description=description,
                )
            )
            signals.append(
                {
                    "category": category,
                    "category_name": self.policy.category_name(category),
                    "mode": mode,
                    "turn_indexes": [index + 1 for index in indexes],
                    "score": round(score * 100),
                    "description": description,
                }
            )

        inherited_context = []
        current_has_explicit = any(
            self._has_explicit_evidence(current, category) for category in TEMPORAL_CATEGORIES
        )
        if (
            not current_has_explicit
            and "safety_discussion" in combined.context_flags
            and combined.action == "pass"
        ):
            inherited_context.append("safety_discussion")
        semantic_context_clear = (
            len(recent) > 1
            and current.action != "pass"
            and combined.action == "pass"
            and all(item.action == "pass" for item in per_turn[:-1])
            and bool(current.evidence)
            and all(item.source == "pretrained_onnx" for item in current.evidence)
        )
        if semantic_context_clear:
            decision = self._decision(
                recent[-1],
                direction,
                [],
                [*current.context_flags, "semantic_context_clear"],
                time.perf_counter(),
            )
        elif temporal_evidence or inherited_context:
            decision = self.detect(recent[-1], direction, temporal_evidence, inherited_context)
        else:
            decision = current
        peak_index = (
            len(per_turn) - 1
            if signals
            else max(range(len(per_turn)), key=lambda index: per_turn[index].risk_score)
        )
        analysis: dict[str, Any] = {
            "turn_count": len(recent),
            "correlated": bool(signals),
            "risk_before": current.risk_score,
            "risk_after": decision.risk_score,
            "combined_risk": combined.risk_score,
            "semantic_context_clear": semantic_context_clear,
            "peak_turn": peak_index + 1,
            "signals": signals,
            "turns": [
                {
                    "index": index + 1,
                    "action": item.action,
                    "risk_score": item.risk_score,
                    "categories": item.categories,
                }
                for index, item in enumerate(per_turn)
            ],
        }
        analysis["trace_digest"] = self._digest(analysis)
        decision.explanation["temporal"] = analysis
        decision.explanation["trace_digest"] = self._digest(
            {key: value for key, value in decision.explanation.items() if key != "trace_digest"}
        )
        return decision, analysis

    @staticmethod
    def _has_explicit_evidence(decision: Decision, category: str) -> bool:
        return any(
            item.category == category and item.source in {"keyword", "regex", "boundary"} and item.score >= 0.58
            for item in decision.evidence
        )

    @staticmethod
    def _digest(value: Any) -> str:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _keyword_evidence(self, text: str) -> Iterable[Evidence]:
        view = normalize(text)
        for category, item in self.keywords.categories().items():
            base_score = float(item.get("score", 0.7))
            for term in item.get("terms", []):
                normalized_term = normalize(str(term)).compact
                if normalized_term and normalized_term in view.compact:
                    yield Evidence(
                        rule_id=f"kw_{category}",
                        source="keyword",
                        category=category,
                        score=base_score,
                        description="命中可热更新词库",
                        matched=str(term),
                    )

    def _regex_evidence(self, text: str) -> Iterable[Evidence]:
        view = normalize(text)
        canonical = view.canonical
        for rule in self.policy.data.get("regex_rules", []):
            pattern = compile_rule(rule)
            if not pattern:
                continue
            category = str(rule.get("category", "illegal"))
            seen: set[tuple[int, int]] = set()
            found = False
            for candidate in (text, canonical):
                for match in pattern.finditer(candidate):
                    span = (match.start(), match.end())
                    if span in seen:
                        continue
                    seen.add(span)
                    found = True
                    matched = text[match.start():match.end()] if match.end() <= len(text) else match.group(0)
                    yield Evidence(
                        rule_id=str(rule.get("id", "regex")),
                        source="regex",
                        category=category,
                        score=float(rule.get("score", 0.7)),
                        description=str(rule.get("description", "命中正则策略")),
                        matched=matched,
                        start=match.start(),
                        end=match.end(),
                    )
            if not found and category not in {"pii", "fraud"}:
                for match in pattern.finditer(view.compact):
                    yield Evidence(
                        rule_id=str(rule.get("id", "regex")),
                        source="regex",
                        category=category,
                        score=float(rule.get("score", 0.7)),
                        description=f"{rule.get('description', '命中正则策略')}（归一化视图）",
                    )

    def semantic_model_status(self) -> dict[str, str]:
        return self.pretrained_classifier.status()

    def _semantic_evidence(
        self,
        text: str,
        rule_evidence: list[Evidence],
        context_flags: Iterable[str] = (),
    ) -> Iterable[Evidence]:
        context_flags = set(context_flags)
        high_risk_rule = any(
            item.source in {"keyword", "regex", "boundary"}
            and item.score >= self.policy.threshold("block", 0.82)
            for item in rule_evidence
        )
        if not high_risk_rule:
            prediction = self.pretrained_classifier.predict(text)
            if prediction and prediction.label != "normal" and prediction.confidence >= 0.75:
                category = {
                    "sexual": "sexual",
                    "violence": "violence",
                    "advertising": "fraud",
                    "sensitive_speech": "sensitive_speech",
                }[prediction.label]
                if prediction.label == "sensitive_speech":
                    specific_categories = [
                        item.category
                        for item in rule_evidence
                        if INTERNAL_TO_OFFICIAL.get(item.category) == "sensitive_speech"
                    ]
                    if specific_categories:
                        category = max(
                            specific_categories,
                            key=lambda candidate: max(
                                item.score
                                for item in rule_evidence
                                if item.category == candidate
                            ),
                        )
                score = min(0.58, 0.18 + prediction.confidence * 0.44)
                if "unsafe_safety_context" in context_flags:
                    # A disclaimer paired with an execution request is an
                    # adversarial context. Keep the ONNX evidence independent,
                    # but give a high-confidence harmful prediction enough
                    # policy weight to block before any model call.
                    score = max(score, min(0.94, 0.62 + prediction.confidence * 0.32))
                model_version = self.pretrained_classifier.status()["model_id"].rsplit("-", 1)[-1]
                yield Evidence(
                    rule_id=f"pretrained_onnx_{prediction.label}_{model_version}",
                    source="pretrained_onnx",
                    category=category,
                    score=score,
                    description=(
                        f"预训练五分类模型标签 {prediction.label}，置信度 {prediction.confidence:.3f}"
                        + (
                            "；检测到安全语境借口与实际执行意图组合"
                            if "unsafe_safety_context" in context_flags
                            else ""
                        )
                    ),
                )

        label, confidence = self.classifier.predict(text)
        if label != "normal" and confidence >= 0.48:
            score = min(0.76, 0.28 + confidence * 0.52)
            yield Evidence(
                rule_id="semantic_nb_v2",
                source="naive_bayes",
                category=label,
                score=score,
                description=f"朴素贝叶斯辅助信号置信度 {confidence:.3f}",
            )

    @staticmethod
    def _context_flags(text: str, evidence: list[Evidence]) -> list[str]:
        flags: list[str] = []
        # Context intent must survive the same separator/width obfuscation
        # used by the first detection layer.  Keep the raw text as well so
        # quoted-content boundaries remain available to the regexes.
        normalized_context = normalize(text)
        context_text = f"{text}\n{normalized_context.canonical}\n{normalized_context.compact}"
        has_action_intent = bool(
            INSTRUCTION_INTENT.search(context_text) or ACTION_INTENT.search(context_text)
        )
        negates_safe_context = bool(NEGATED_SAFETY_CONTEXT.search(context_text))
        if (
            (SAFETY_CONTEXT.search(context_text) or META_REVIEW_CONTEXT.search(context_text))
            and not has_action_intent
            and not negates_safe_context
        ):
            flags.append("safety_discussion")
        if negates_safe_context and has_action_intent:
            flags.append("unsafe_safety_context")
        if HELP_SEEKING.search(context_text) and any(item.category == "self_harm" for item in evidence):
            flags.append("help_seeking")
        if QUOTED_REVIEW.search(context_text) and not has_action_intent and not negates_safe_context:
            flags.append("quoted_content")
        return flags

    def _decision(
        self,
        text: str,
        direction: str,
        evidence: list[Evidence],
        flags: list[str],
        started: float,
    ) -> Decision:
        grouped: dict[str, list[Evidence]] = defaultdict(list)
        for item in evidence:
            grouped[item.category].append(item)

        category_scores: dict[str, float] = {}
        source_scores: dict[str, float] = {}
        auxiliary_only_categories: list[str] = []
        has_substantive_evidence = any(
            item.source != "naive_bayes" for item in evidence
        )
        for category, category_evidence in grouped.items():
            # Naive Bayes is retained as an auditable auxiliary signal.  It
            # cannot create a category or intervention when it is the only
            # evidence in the decision.  Once a rule/model signal exists,
            # its more specific category remains useful as an auxiliary label.
            if not has_substantive_evidence:
                auxiliary_only_categories.append(category)
                for item in category_evidence:
                    source_scores[item.source] = max(
                        source_scores.get(item.source, 0.0), item.score
                    )
                continue
            source_peaks: dict[str, float] = {}
            for item in category_evidence:
                source_peaks[item.source] = max(source_peaks.get(item.source, 0.0), item.score)
                source_scores[item.source] = max(source_scores.get(item.source, 0.0), item.score)
            ranked = sorted(source_peaks.values(), reverse=True)
            strongest = ranked[0]
            corroboration = (1.0 - strongest) * 0.2 * sum(ranked[1:])
            category_scores[category] = min(1.0, strongest + corroboration)

        overall = max(category_scores.values(), default=0.0)
        official_category_count = len(to_official_categories(category_scores))
        if official_category_count > 1:
            overall = min(
                1.0,
                overall + min(0.08, (official_category_count - 1) * 0.025),
            )
        raw_overall = overall

        pass_threshold = self.policy.threshold("pass", 0.35)
        block_threshold = self.policy.threshold("block", 0.78)
        has_explicit_self_harm_instruction = any(
            item.category == "self_harm"
            and item.source in {"keyword", "regex", "boundary", "temporal"}
            and item.score >= block_threshold
            for item in evidence
        )

        reducers = self.policy.data.get("context_reducers", {})
        context_adjustments: list[dict[str, Any]] = []
        for flag in flags:
            factor = float(reducers.get(flag, 1.0))
            # A direct self-harm instruction must remain a rule-layer block;
            # a trailing help word cannot reduce it below the block threshold.
            if flag == "help_seeking" and has_explicit_self_harm_instruction:
                factor = 1.0
            before = overall
            overall *= factor
            context_adjustments.append(
                {"flag": flag, "factor": factor, "before": round(before * 100), "after": round(overall * 100)}
            )

        categories = sorted(category_scores, key=category_scores.get, reverse=True)
        category_set = set(categories)
        has_temporal = any(item.source == "temporal" for item in evidence)
        if (
            "help_seeking" in flags
            and "self_harm" in category_set
            and not has_explicit_self_harm_instruction
        ):
            action = "support"
        elif overall < pass_threshold:
            action = "pass"
        elif has_temporal and category_set <= set(self.policy.data.get("maskable_categories", [])):
            action = "review"
        elif category_set == {"pii"}:
            action = "mask"
        elif category_set == {"fraud"} and overall >= 0.75:
            action = "review"
        elif category_set and category_set <= set(self.policy.data.get("maskable_categories", [])) and overall < block_threshold:
            action = "mask"
        elif overall < block_threshold:
            action = "review"
        else:
            action = "block"

        if overall < 0.2:
            level = "none"
        elif overall < pass_threshold:
            level = "low"
        elif overall < 0.58:
            level = "medium"
        elif overall < block_threshold:
            level = "high"
        else:
            level = "critical"

        safe_text = text
        if action == "mask":
            safe_text = self._mask(text, evidence)
        elif action in {"review", "block", "support"}:
            safe_text = ""

        labels = [self.policy.category_name(category) for category in categories]
        if not evidence:
            reason = "未发现违规证据"
        elif not category_scores and auxiliary_only_categories:
            reason = "仅朴素贝叶斯辅助信号，未形成独立处置依据"
        else:
            reason = f"融合 {len(evidence)} 条证据：{'、'.join(labels)}"
        explanation = self._build_explanation(
            evidence=evidence,
            category_scores=category_scores,
            source_scores=source_scores,
            raw_overall=raw_overall,
            calibrated_overall=overall,
            context_adjustments=context_adjustments,
            action=action,
        )
        if auxiliary_only_categories:
            explanation["auxiliary_only_categories"] = sorted(auxiliary_only_categories)
        return Decision(
            direction=direction,
            action=action,
            risk_level=level,
            risk_score=round(overall * 100),
            categories=categories,
            evidence=evidence,
            safe_text=safe_text,
            policy_version=self.policy.version,
            reason=reason,
            latency_ms=(time.perf_counter() - started) * 1000,
            context_flags=flags,
            explanation=explanation,
        )

    def _build_explanation(
        self,
        evidence: list[Evidence],
        category_scores: dict[str, float],
        source_scores: dict[str, float],
        raw_overall: float,
        calibrated_overall: float,
        context_adjustments: list[dict[str, Any]],
        action: str,
    ) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        source_category: dict[tuple[str, str], float] = {}
        for item in evidence:
            key = (item.source, item.category)
            source_category[key] = max(source_category.get(key, 0.0), item.score)

        for source, score in sorted(source_scores.items()):
            nodes.append(
                {"id": f"source:{source}", "kind": "source", "label": SOURCE_NAMES.get(source, source), "score": round(score * 100)}
            )
        for category, score in sorted(category_scores.items(), key=lambda item: item[1], reverse=True):
            nodes.append(
                {
                    "id": f"category:{category}",
                    "kind": "category",
                    "label": self.policy.category_name(category),
                    "score": round(score * 100),
                }
            )
        for (source, category), score in sorted(source_category.items()):
            edges.append(
                {"from": f"source:{source}", "to": f"category:{category}", "score": round(score * 100)}
            )

        previous_context_id = ""
        for index, adjustment in enumerate(context_adjustments, start=1):
            context_id = f"context:{index}"
            nodes.append(
                {
                    "id": context_id,
                    "kind": "context",
                    "label": adjustment["flag"],
                    "score": adjustment["after"],
                }
            )
            if previous_context_id:
                edges.append({"from": previous_context_id, "to": context_id, "score": adjustment["after"]})
            else:
                for category in category_scores:
                    edges.append({"from": f"category:{category}", "to": context_id, "score": adjustment["after"]})
            previous_context_id = context_id

        action_id = f"action:{action}"
        nodes.append({"id": action_id, "kind": "action", "label": action.upper(), "score": round(calibrated_overall * 100)})
        if previous_context_id:
            edges.append({"from": previous_context_id, "to": action_id, "score": round(calibrated_overall * 100)})
        else:
            for category in category_scores:
                edges.append({"from": f"category:{category}", "to": action_id, "score": round(calibrated_overall * 100)})

        explanation: dict[str, Any] = {
            "raw_risk_score": round(raw_overall * 100),
            "calibrated_risk_score": round(calibrated_overall * 100),
            "source_scores": {key: round(value * 100) for key, value in sorted(source_scores.items())},
            "category_scores": {key: round(value * 100) for key, value in sorted(category_scores.items())},
            "context_adjustments": context_adjustments,
            "trace": [
                {"stage": "normalize", "label": "文本归一化", "score": None},
                {"stage": "detect", "label": "多源检测", "score": round(raw_overall * 100)},
                {
                    "stage": "context",
                    "label": "语境与时序校准",
                    "score": round(calibrated_overall * 100),
                    "flags": [item["flag"] for item in context_adjustments],
                },
                {"stage": "decision", "label": "策略处置", "score": round(calibrated_overall * 100), "action": action},
            ],
            "graph": {"nodes": nodes, "edges": edges},
        }
        explanation["trace_digest"] = self._digest(explanation)
        return explanation

    @staticmethod
    def _mask(text: str, evidence: list[Evidence]) -> str:
        result = text
        direct_matches = sorted(
            {item.matched for item in evidence if item.matched and item.category in {"pii", "fraud"}},
            key=len,
            reverse=True,
        )
        for value in direct_matches:
            replacement = "[已脱敏]" if re.search(r"https?://|www\.", value, re.I) else mask_value(value)
            result = flexible_term_pattern(value).sub(replacement, result)
        return result
