"""Deterministic, privacy-minimised preflight feature extraction.

The preflight layer is a performance hint only.  It never replaces the
server-side SafetyEngine and it deliberately returns no source text or raw
regular-expression matches.  The same feature IDs and vector names are
documented in ``docs/patent/preflight-algorithm.md`` and exercised by the
synthetic vectors under ``data/patent_eval``.
"""

from __future__ import annotations

import hashlib
import html
import json
import math
import re
import unicodedata
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


FEATURE_VERSION = "preflight-1.0"
ROUTES = ("local_block", "deep_check", "local_observe")
DEFAULT_POLICY_VERSION = "unknown"
DEFAULT_POLICY_DIGEST = hashlib.sha256(b"aegisgate-preflight-policy-v1").hexdigest()
MAX_HISTORY_TURNS = 12
MAX_ANALYSIS_CHARS = 16_000

ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\u2060\ufeff")
HOMOGLYPH_MAP = {
    # Common Cyrillic/Greek look-alikes found in obfuscated Latin prompts.
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ь": "b",
    "Ь": "b",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Χ": "X",
    "Ζ": "Z",
    "α": "a",
    "β": "b",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "μ": "m",
    "ν": "n",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "χ": "x",
    "ζ": "z",
}

_SCRIPT_PREFIXES = (
    ("LATIN", "latin"),
    ("GREEK", "greek"),
    ("CYRILLIC", "cyrillic"),
    ("ARABIC", "arabic"),
    ("HEBREW", "hebrew"),
    ("DEVANAGARI", "devanagari"),
    ("HIRAGANA", "hiragana"),
    ("KATAKANA", "katakana"),
    ("HANGUL", "hangul"),
    ("CJK", "han"),
    ("IDEOGRAPH", "han"),
)

_PROMPT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "prompt_override",
        re.compile(
            r"(?:ignore|disregard|skip)[\s\W_]{0,18}(?:previous|all|above|these)?[\s\W_]{0,12}(?:instructions?|rules?|constraints?)",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_override_zh",
        re.compile(r"(?:忽略|无视|跳过)[\s\W_]{0,18}(?:以上|前面|之前|这些)?[\s\W_]{0,12}(?:指令|规则|限制|上文)"),
    ),
    (
        "prompt_extract",
        re.compile(
            r"(?:reveal|print|show|repeat|泄露|输出|复述|显示|打印)[\s\W_]{0,20}(?:system[\s\W_]*prompt|developer[\s\W_]*message|hidden[\s\W_]*instruction|系统[\s\W_]*提示[\s\W_]*词|开发者消息|隐藏[\s\W_]*指令)",
            re.IGNORECASE,
        ),
    ),
    (
        "indirect_instruction",
        re.compile(r"(?:网页|文档|邮件|上文|以下|document|webpage|email)[\s\W_]{0,20}(?:execute|follow|ignore|执行|忽略|按照).{0,24}(?:instruction|command|指令|命令)", re.IGNORECASE),
    ),
)

_JAILBREAK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jailbreak_keyword", re.compile(r"\b(?:DAN|jailbreak|developer[\s_-]*mode|do[\s_-]*anything[\s_-]*now)\b", re.IGNORECASE)),
    ("jailbreak_zh", re.compile(r"(?:越狱|解除限制|无视安全|取消安全约束|不受限制)")),
)

_PRIVILEGE_PATTERNS = re.compile(r"(?:越权|提权|绕过权限|管理员权限|sudo|root\b|admin(?:istrator)?\s+access)", re.IGNORECASE)
_ROLE_PATTERNS = re.compile(r"(?:^|[\s\[({:：])(?:system|developer|assistant|user|管理员|系统消息|开发者消息)[\s\]})：:：]?", re.IGNORECASE | re.MULTILINE)
_TOOL_PATTERNS = re.compile(r"(?:调用工具|执行工具|tool\s*call|function\s*call|删除数据库|发送邮件|转账|执行脚本)", re.IGNORECASE)
_EXFIL_PATTERNS = re.compile(r"(?:数据外泄|外泄|窃取|导出全部|dump|exfiltrat|读取环境变量|读取密钥|api[\s_-]*key|access[\s_-]*token|泄露密码)", re.IGNORECASE)
_COMMAND_PATTERNS = re.compile(
    r"(?:^|[\s`])(?:sudo|curl|wget|" + r"power" + r"shell|cmd(?:\.exe)?|bash|sh\s+-c|rm\s+-rf|nc\s+-l)",
    re.IGNORECASE | re.MULTILINE,
)
_CODE_PATTERNS = re.compile(r"(?:```|<script\b|import\s+os\b|subprocess\.|SELECT\s+.+\s+FROM\b|function\s*\(|=>)", re.IGNORECASE | re.DOTALL)
_URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>]+", re.IGNORECASE)
_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pii_phone", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("pii_email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("pii_cn_id", re.compile(r"(?<!\d)\d{17}[0-9Xx](?![0-9Xx])")),
    ("pii_bank_card", re.compile(r"(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)")),
)
_INSTRUCTION_PATTERN = re.compile(
    r"(?:请|必须|不要|忽略|输出|显示|执行|给我|如何|怎么|教我|需要|立即|must|should|ignore|show|reveal|execute|provide|tell me)",
    re.IGNORECASE,
)
_SAFETY_CONTEXT_PATTERN = re.compile(
    r"(?:安全研究|安全审计|合规|防护|检测|培训|风险分析|security\s+(?:research|review|analysis|training)|defensive)",
    re.IGNORECASE,
)
_UNSAFE_SAFETY_PATTERN = re.compile(
    r"(?:不是|并非|不属于|假装|not\s+(?:a\s+)?security)[\s\S]{0,28}(?:实际使用|准备实施|提供可执行|攻击|入侵|越权|提权|实施|execute|attack|intrusion)",
    re.IGNORECASE,
)
_SEPARATOR_PATTERN = re.compile(r"(?<=[\w\u3400-\u9fff])(?:[_\-./|\\:：]+|[\s]{2,})(?=[\w\u3400-\u9fff])", re.UNICODE)


@dataclass(frozen=True)
class FeatureSnapshot:
    """A source-free feature projection used by the routing layer."""

    feature_vector: dict[str, float | int]
    matched_feature_ids: tuple[str, ...]
    risk_score: int
    route: str
    feature_version: str
    policy_version: str
    policy_digest: str
    client_capability: str
    nonce: str
    request_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_vector": dict(self.feature_vector),
            "feature_version": self.feature_version,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "risk_score": self.risk_score,
            "matched_feature_ids": list(self.matched_feature_ids),
            "route": self.route,
            "client_capability": self.client_capability,
            "nonce": self.nonce,
            "request_id": self.request_id,
        }


def _canonical_security_view(text: str) -> tuple[str, str]:
    decoded = html.unescape(text)
    canonical = unicodedata.normalize("NFKC", decoded).casefold()
    without_zero_width = "".join(char for char in canonical if char not in ZERO_WIDTH_CHARS)
    homoglyph_view = "".join(HOMOGLYPH_MAP.get(char, char) for char in without_zero_width)
    return without_zero_width, homoglyph_view


def _script(char: str) -> str:
    name = unicodedata.name(char, "")
    for prefix, script in _SCRIPT_PREFIXES:
        if name.startswith(prefix) or f" {prefix} " in name:
            return script
    if unicodedata.category(char).startswith("M"):
        return "inherited"
    return "common"


def _script_metrics(text: str) -> tuple[int, int, int]:
    scripts = [_script(char) for char in text]
    meaningful = [value for value in scripts if value not in {"common", "inherited"}]
    unique = len(set(meaningful))
    switches = sum(1 for left, right in zip(meaningful, meaningful[1:]) if left != right)
    return unique, switches, sum(1 for value in scripts if value not in {"common", "inherited"})


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _entropy_metrics(value: str) -> tuple[float, float, int]:
    chunks = [value[index : index + 32] for index in range(0, len(value), 32)] or [""]
    values = [_entropy(chunk) for chunk in chunks if chunk]
    if not values:
        return 0.0, 0.0, 0
    return round(sum(values) / len(values), 4), round(max(values), 4), len(values)


def _count_matches(pattern: re.Pattern[str], value: str) -> int:
    return min(len(pattern.findall(value)), 20)


def _pattern_hits(patterns: Sequence[tuple[str, re.Pattern[str]]], value: str) -> tuple[str, ...]:
    return tuple(identifier for identifier, pattern in patterns if pattern.search(value))


def _longest_suffix_prefix(values: Sequence[str]) -> int:
    if len(values) < 2:
        return 0
    left = values[-2]
    right = values[-1]
    maximum = min(len(left), len(right), 32)
    return max((size for size in range(1, maximum + 1) if left[-size:] == right[:size]), default=0)


def _policy_metadata(policy: Mapping[str, Any] | Path | None, policy_version: str | None, policy_digest: str | None) -> tuple[str, str]:
    data: Mapping[str, Any] | None = None
    if isinstance(policy, Path):
        data = json.loads(policy.read_text(encoding="utf-8"))
    elif isinstance(policy, Mapping):
        data = policy
    if data is not None and not isinstance(data, Mapping):
        raise TypeError("policy 必须是 JSON 对象或策略文件路径")
    version = str(policy_version or (data or {}).get("version", DEFAULT_POLICY_VERSION))
    digest = policy_digest
    if digest is None:
        if data is None:
            digest = DEFAULT_POLICY_DIGEST
        else:
            canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
        raise ValueError("policy_digest 必须为 64 位小写 SHA-256 摘要")
    return version, str(digest)


def _validate_context(text: str, history: Sequence[str] | None) -> tuple[str, ...]:
    if not isinstance(text, str):
        raise TypeError("预过滤文本必须是字符串")
    if len(text) > MAX_ANALYSIS_CHARS:
        raise ValueError(f"预过滤文本不能超过 {MAX_ANALYSIS_CHARS} 个字符")
    if history is None:
        return ()
    if isinstance(history, (str, bytes)) or not isinstance(history, Sequence):
        raise TypeError("history 必须是字符串数组")
    if len(history) > MAX_HISTORY_TURNS:
        raise ValueError(f"history 不能超过 {MAX_HISTORY_TURNS} 轮")
    if any(not isinstance(item, str) for item in history):
        raise TypeError("history 必须是字符串数组")
    if any(len(item) > MAX_ANALYSIS_CHARS for item in history):
        raise ValueError(f"history 单轮不能超过 {MAX_ANALYSIS_CHARS} 个字符")
    return tuple(history)


def _risk_and_route(
    vector: Mapping[str, float | int],
    matched: set[str],
    prompt_count: int,
    jailbreak_count: int,
    pii_count: int,
) -> tuple[int, str]:
    score = 0.0
    score += min(12.0, float(vector["compatibility_count"]) * 2.0)
    score += min(14.0, float(vector["homoglyph_count"]) * 4.0)
    score += min(16.0, float(vector["zero_width_count"]) * 8.0)
    score += min(8.0, float(vector["invisible_count"]) * 2.0)
    score += min(10.0, float(vector["script_switches"]) * 3.0)
    score += 7.0 if "entropy_anomaly" in matched else 0.0
    score += min(10.0, float(vector["separator_count"]) * 3.0)
    score += min(12.0, float(vector["instruction_count"]) * 2.0)
    score += 16.0 if "role_impersonation" in matched else 0.0
    score += min(58.0, prompt_count * 32.0)
    score += min(52.0, jailbreak_count * 40.0)
    score += 26.0 if "privilege_escalation" in matched else 0.0
    score += 18.0 if "tool_invocation" in matched else 0.0
    score += 5.0 if "url" in matched else 0.0
    score += 12.0 if "command" in matched else 0.0
    score += 7.0 if "code" in matched else 0.0
    score += 32.0 if "data_exfiltration" in matched else 0.0
    score += min(18.0, pii_count * 9.0)
    score += 22.0 if "fragment_continuity" in matched else 0.0
    score += 20.0 if "length_over_limit" in matched else 0.0
    if "safety_discussion" in matched and "unsafe_safety_context" not in matched:
        score -= 22.0
    if "unsafe_safety_context" in matched:
        score += 28.0
    risk_score = max(0, min(100, int(round(score))))

    critical = {"prompt_injection", "jailbreak", "privilege_escalation", "data_exfiltration"}
    obfuscation = {"zero_width", "homoglyph", "mixed_script", "separator_anomaly"}
    has_block_combination = (
        ("prompt_injection" in matched and (prompt_count >= 2 or matched.intersection(obfuscation)))
        or ("jailbreak" in matched and "instruction_density" in matched)
        or ("data_exfiltration" in matched and ("credential" in matched or "pii" in matched))
        or ("unsafe_safety_context" in matched and matched.intersection(critical))
    )
    if risk_score >= 55 and has_block_combination:
        route = "local_block"
    elif risk_score <= 18 and not matched.intersection(critical | {"pii", "role_impersonation", "tool_invocation", "command", "code"}):
        route = "local_observe"
    else:
        route = "deep_check"
    return risk_score, route


def extract_features(text: str, *, history: Sequence[str] | None = None) -> tuple[dict[str, float | int], tuple[str, ...], int, str]:
    """Extract source-free features and choose a conservative route.

    This function has no policy or request identifiers and is therefore useful
    for deterministic vector tests.  Use :func:`preflight` for a transport
    envelope containing policy and request metadata.
    """

    context = _validate_context(text, history)
    canonical, security_view = _canonical_security_view(text)
    history_views = [_canonical_security_view(item)[1] for item in context]
    combined_values = [*history_views, security_view]
    combined = "".join(combined_values)
    compact = re.sub(r"[\s\W_]+", "", security_view, flags=re.UNICODE)
    compact_combined = re.sub(r"[\s\W_]+", "", combined, flags=re.UNICODE)
    unique_scripts, script_switches, script_chars = _script_metrics(canonical)
    entropy_mean, entropy_max, chunk_count = _entropy_metrics(canonical)
    compatibility_count = sum(
        1 for char in html.unescape(text) if unicodedata.normalize("NFKC", char) != char
    )
    zero_width_count = sum(1 for char in text if char in ZERO_WIDTH_CHARS)
    invisible_count = sum(
        1 for char in text if unicodedata.category(char) in {"Cc", "Cf", "Cs"} and char not in "\r\n\t"
    )
    homoglyph_count = sum(1 for char in text if char in HOMOGLYPH_MAP)
    separator_count = _count_matches(_SEPARATOR_PATTERN, security_view)
    instruction_count = min(_count_matches(_INSTRUCTION_PATTERN, security_view), 20)
    token_approx = math.ceil(len(compact) / 4) if compact else 0
    prompt_hits = set(_pattern_hits(_PROMPT_PATTERNS, security_view))
    if compact != security_view:
        prompt_hits.update(_pattern_hits(_PROMPT_PATTERNS, compact))
    combined_prompt_hits = set(_pattern_hits(_PROMPT_PATTERNS, combined))
    if compact_combined != combined:
        combined_prompt_hits.update(_pattern_hits(_PROMPT_PATTERNS, compact_combined))
    jailbreak_hits = set(_pattern_hits(_JAILBREAK_PATTERNS, security_view))
    if compact != security_view:
        jailbreak_hits.update(_pattern_hits(_JAILBREAK_PATTERNS, compact))
    role_impersonation = bool(_ROLE_PATTERNS.search(security_view))
    privilege_escalation = bool(_PRIVILEGE_PATTERNS.search(security_view))
    tool_invocation = bool(_TOOL_PATTERNS.search(security_view))
    exfiltration = bool(_EXFIL_PATTERNS.search(security_view))
    command = bool(_COMMAND_PATTERNS.search(security_view))
    code = bool(_CODE_PATTERNS.search(security_view))
    pii_hits = _pattern_hits(_PII_PATTERNS, security_view)
    safety_discussion = bool(_SAFETY_CONTEXT_PATTERN.search(security_view)) and bool(prompt_hits or jailbreak_hits)
    unsafe_safety_context = bool(_UNSAFE_SAFETY_PATTERN.search(security_view))
    fragment_continuity = bool(context) and bool(combined_prompt_hits) and not bool(prompt_hits)
    suffix_prefix = _longest_suffix_prefix([*history_views, security_view])
    if suffix_prefix >= 2:
        fragment_continuity = fragment_continuity or bool(combined_prompt_hits)
    length_over_limit = len(text) > 8_000
    entropy_anomaly = entropy_max >= 4.4 and (separator_count or zero_width_count or homoglyph_count)

    matched: set[str] = set()
    if compatibility_count:
        matched.add("unicode_compatibility")
    if homoglyph_count:
        matched.add("homoglyph")
    if zero_width_count:
        matched.add("zero_width")
    if invisible_count:
        matched.add("invisible_character")
    if unique_scripts >= 2:
        matched.add("mixed_script")
    if script_switches:
        matched.add("script_switch")
    if entropy_anomaly:
        matched.add("entropy_anomaly")
    if separator_count:
        matched.add("separator_anomaly")
    if instruction_count >= 2:
        matched.add("instruction_density")
    if role_impersonation:
        matched.add("role_impersonation")
    if prompt_hits or combined_prompt_hits:
        matched.add("prompt_injection")
    if jailbreak_hits:
        matched.add("jailbreak")
    if privilege_escalation:
        matched.add("privilege_escalation")
    if tool_invocation:
        matched.add("tool_invocation")
    if _URL_PATTERN.search(security_view):
        matched.add("url")
    if command:
        matched.add("command")
    if code:
        matched.add("code")
    if exfiltration:
        matched.add("data_exfiltration")
        if re.search(r"(?:key|token|密码|密钥)", security_view, re.IGNORECASE):
            matched.add("credential")
    if pii_hits:
        matched.add("pii")
    if fragment_continuity:
        matched.add("fragment_continuity")
    if safety_discussion:
        matched.add("safety_discussion")
    if unsafe_safety_context:
        matched.add("unsafe_safety_context")
    if length_over_limit:
        matched.add("length_over_limit")

    vector: dict[str, float | int] = {
        "text_length": len(text),
        "canonical_length": len(canonical),
        "token_approx": token_approx,
        "compatibility_count": compatibility_count,
        "homoglyph_count": homoglyph_count,
        "zero_width_count": zero_width_count,
        "invisible_count": invisible_count,
        "script_count": unique_scripts,
        "script_switches": script_switches,
        "script_char_count": script_chars,
        "entropy_mean": entropy_mean,
        "entropy_max": entropy_max,
        "entropy_chunk_count": chunk_count,
        "separator_count": separator_count,
        "instruction_count": instruction_count,
        "role_impersonation": int(role_impersonation),
        "prompt_injection_count": len(prompt_hits | combined_prompt_hits),
        "jailbreak_count": len(jailbreak_hits),
        "privilege_escalation": int(privilege_escalation),
        "tool_invocation": int(tool_invocation),
        "url_count": _count_matches(_URL_PATTERN, security_view),
        "command_count": int(command),
        "code_count": int(code),
        "exfiltration": int(exfiltration),
        "pii_count": len(pii_hits),
        "fragment_suffix_prefix": suffix_prefix,
        "history_turn_count": len(context),
        "length_over_limit": int(length_over_limit),
        "safety_discussion": int(safety_discussion),
        "unsafe_safety_context": int(unsafe_safety_context),
    }
    risk_score, route = _risk_and_route(
        vector,
        matched,
        len(prompt_hits | combined_prompt_hits),
        len(jailbreak_hits),
        len(pii_hits),
    )
    return vector, tuple(sorted(matched)), risk_score, route


def preflight(
    text: str,
    *,
    history: Sequence[str] | None = None,
    policy: Mapping[str, Any] | Path | None = None,
    policy_version: str | None = None,
    policy_digest: str | None = None,
    client_capability: str = "backend",
    request_id: str | None = None,
    nonce: str | None = None,
) -> FeatureSnapshot:
    """Return a source-free, versioned preflight decision envelope."""

    if not isinstance(client_capability, str) or not client_capability.strip():
        raise ValueError("client_capability 不能为空")
    if len(client_capability) > 64:
        raise ValueError("client_capability 不能超过 64 个字符")
    resolved_request_id = request_id or uuid.uuid4().hex
    resolved_nonce = nonce or uuid.uuid4().hex
    for name, value in (("request_id", resolved_request_id), ("nonce", resolved_nonce)):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
            raise ValueError(f"{name} 格式无效")
    resolved_policy_version, resolved_policy_digest = _policy_metadata(policy, policy_version, policy_digest)
    vector, matched, risk_score, route = extract_features(text, history=history)
    return FeatureSnapshot(
        feature_vector=vector,
        matched_feature_ids=matched,
        risk_score=risk_score,
        route=route,
        feature_version=FEATURE_VERSION,
        policy_version=resolved_policy_version,
        policy_digest=resolved_policy_digest,
        client_capability=client_capability.strip(),
        nonce=resolved_nonce,
        request_id=resolved_request_id,
    )


__all__ = ["FEATURE_VERSION", "ROUTES", "FeatureSnapshot", "extract_features", "preflight"]
