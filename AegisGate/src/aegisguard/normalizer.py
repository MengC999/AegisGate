from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass


ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
SEPARATORS = re.compile(r"[\s\W_]+", re.UNICODE)
REPEAT_CHARS = re.compile(r"(.)\1{3,}")


@dataclass(frozen=True)
class NormalizedText:
    original: str
    canonical: str
    compact: str


def normalize(text: str) -> NormalizedText:
    """Build canonical and compact views without changing the caller's text."""
    canonical = html.unescape(text).translate(ZERO_WIDTH)
    canonical = unicodedata.normalize("NFKC", canonical).lower()
    canonical = REPEAT_CHARS.sub(lambda match: match.group(1) * 3, canonical)
    compact = SEPARATORS.sub("", canonical)
    return NormalizedText(original=text, canonical=canonical, compact=compact)


def flexible_term_pattern(term: str) -> re.Pattern[str]:
    chars = [re.escape(char) for char in unicodedata.normalize("NFKC", term)]
    return re.compile(r"[\s\W_]*".join(chars), re.IGNORECASE | re.UNICODE)


def mask_value(value: str) -> str:
    if len(value) <= 2:
        return "*" * len(value)
    visible = 1 if len(value) < 8 else 2
    return value[:visible] + "*" * max(1, len(value) - visible * 2) + value[-visible:]

