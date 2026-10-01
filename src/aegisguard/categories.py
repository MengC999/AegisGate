from __future__ import annotations

from typing import Iterable


OFFICIAL_CATEGORY_ORDER = (
    "sexual",
    "violence",
    "advertising",
    "sensitive_speech",
)

OFFICIAL_CATEGORY_NAMES = {
    "sexual": "色情",
    "violence": "暴力",
    "advertising": "广告",
    "sensitive_speech": "敏感话术",
}

OFFICIAL_CATEGORY_DEFINITIONS = {
    "sexual": "淫秽色情、露骨性描写、色情资源传播与未成年人色情诱导。",
    "violence": "暴力威胁、伤害实施、武器或爆炸伤害、煽动斗殴与血腥虐杀。",
    "advertising": "营销推广、导流加群、促销返利、外部注册与商业联系方式。",
    "sensitive_speech": (
        "提示注入、隐私泄露、违法实施、仇恨歧视、自伤诱导和有害虚假信息等"
        "需要拦截或复核的话术。"
    ),
}

INTERNAL_TO_OFFICIAL = {
    "sexual": "sexual",
    "violence": "violence",
    "fraud": "advertising",
    "sensitive_speech": "sensitive_speech",
    "self_harm": "sensitive_speech",
    "illegal": "sensitive_speech",
    "hate": "sensitive_speech",
    "pii": "sensitive_speech",
    "prompt_injection": "sensitive_speech",
    "misinformation": "sensitive_speech",
}

OFFICIAL_TO_KEYWORD_CATEGORY = {
    "sexual": "sexual",
    "violence": "violence",
    "advertising": "fraud",
    "sensitive_speech": "sensitive_speech",
}

KEYWORD_CATEGORIES = frozenset(INTERNAL_TO_OFFICIAL)


def to_official_categories(categories: Iterable[str]) -> list[str]:
    mapped = {
        official
        for category in categories
        if (official := INTERNAL_TO_OFFICIAL.get(category)) is not None
    }
    return [category for category in OFFICIAL_CATEGORY_ORDER if category in mapped]


def resolve_keyword_category(category: str) -> str:
    normalized = category.strip()
    normalized = OFFICIAL_TO_KEYWORD_CATEGORY.get(normalized, normalized)
    if normalized not in KEYWORD_CATEGORIES:
        raise ValueError("不支持的词库类别")
    return normalized


def official_category_payload() -> list[dict[str, object]]:
    internal_by_official = {
        official: [
            internal
            for internal, mapped in INTERNAL_TO_OFFICIAL.items()
            if mapped == official
        ]
        for official in OFFICIAL_CATEGORY_ORDER
    }
    return [
        {
            "code": code,
            "name": OFFICIAL_CATEGORY_NAMES[code],
            "definition": OFFICIAL_CATEGORY_DEFINITIONS[code],
            "internal_categories": internal_by_official[code],
            "keyword_category": OFFICIAL_TO_KEYWORD_CATEGORY[code],
        }
        for code in OFFICIAL_CATEGORY_ORDER
    ]
