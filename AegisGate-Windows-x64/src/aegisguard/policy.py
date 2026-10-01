from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

from .categories import (
    INTERNAL_TO_OFFICIAL,
    OFFICIAL_CATEGORY_NAMES,
    official_category_payload,
    resolve_keyword_category,
)
from .normalizer import normalize
from .storage import ReloadableJson, atomic_save_json, load_json


class SafetyPolicy:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._store = ReloadableJson(path, {})

    @property
    def data(self) -> dict[str, Any]:
        return self._store.get()

    @property
    def version(self) -> str:
        return str(self.data.get("version", "unknown"))

    def threshold(self, name: str, default: float) -> float:
        return float(self.data.get("thresholds", {}).get(name, default))

    def limit(self, name: str, default: int) -> int:
        return int(self.data.get("limits", {}).get(name, default))

    def category_name(self, category: str) -> str:
        fallback = {"sensitive_speech": "敏感话术"}
        return str(self.data.get("category_names", {}).get(category, fallback.get(category, category)))

    def official_categories(self) -> list[dict[str, object]]:
        return official_category_payload()


class KeywordLibrary:
    MAX_TERM_CHARS = 100
    _path_locks: dict[Path, threading.RLock] = {}
    _path_locks_guard = threading.Lock()

    def __init__(self, path: Path) -> None:
        self.path = path
        self._store = ReloadableJson(path, {"version": "unknown", "categories": {}})
        self._write_lock = self._lock_for_path(path)

    @classmethod
    def _lock_for_path(cls, path: Path) -> threading.RLock:
        """Serialize in-process writers that share one persistent word library."""
        resolved = path.resolve()
        with cls._path_locks_guard:
            lock = cls._path_locks.get(resolved)
            if lock is None:
                lock = threading.RLock()
                cls._path_locks[resolved] = lock
            return lock

    @property
    def data(self) -> dict[str, Any]:
        return self._store.get()

    def categories(self) -> dict[str, Any]:
        return dict(self.data.get("categories", {}))

    def add(self, category: str, term: str, score: float | None = None) -> bool:
        category = resolve_keyword_category(self._category_value(category))
        term = self._term_value(term)
        validated_score = self._score_value(score, 0.7) if score is not None else None
        with self._write_lock:
            data = load_json(self.path, {"version": "local", "categories": {}})
            categories = self._categories_value(data)
            item = categories.get(category)
            if item is None:
                item = {"score": validated_score or 0.7, "terms": []}
                categories[category] = item
            self._category_item(category, item)
            keys = {self._term_key(value) for value in item["terms"]}
            if self._term_key(term) in keys:
                return False
            item["terms"].append(term)
            item["terms"].sort(key=self._term_key)
            atomic_save_json(self.path, data)
            self._store.invalidate()
            return True

    def remove(self, category: str, term: str) -> bool:
        category = resolve_keyword_category(self._category_value(category))
        term_key = self._term_key(self._term_value(term))
        with self._write_lock:
            data = load_json(self.path, {"categories": {}})
            categories = self._categories_value(data)
            item = categories.get(category)
            if item is None:
                return False
            self._category_item(category, item)
            match = next(
                (value for value in item["terms"] if self._term_key(value) == term_key),
                None,
            )
            if match is None:
                return False
            item["terms"].remove(match)
            atomic_save_json(self.path, data)
            self._store.invalidate()
            return True

    def import_file(self, path: Path) -> int:
        incoming = load_json(path, {})
        return int(self.import_data(incoming)["added"])

    def import_data(self, incoming: Any) -> dict[str, int]:
        validated = self._validate_import(incoming)
        with self._write_lock:
            data = load_json(self.path, {"version": "local", "categories": {}})
            categories = self._categories_value(data)
            added = 0
            duplicates = 0
            for category, incoming_item in validated.items():
                duplicates += int(incoming_item.get("duplicates", 0))
                current = categories.get(category)
                if current is None:
                    current = {"score": incoming_item["score"], "terms": []}
                    categories[category] = current
                self._category_item(category, current)
                keys = {self._term_key(value) for value in current["terms"]}
                for term in incoming_item["terms"]:
                    key = self._term_key(term)
                    if key in keys:
                        duplicates += 1
                        continue
                    current["terms"].append(term)
                    keys.add(key)
                    added += 1
                current["terms"].sort(key=self._term_key)
            if added:
                atomic_save_json(self.path, data)
                self._store.invalidate()
            return {"added": added, "duplicates": duplicates}

    def api_payload(self) -> dict[str, object]:
        categories: dict[str, object] = {}
        for category, item in self.categories().items():
            if category not in INTERNAL_TO_OFFICIAL or not isinstance(item, dict):
                continue
            official = INTERNAL_TO_OFFICIAL[category]
            categories[category] = {
                "score": item.get("score"),
                "terms": list(item.get("terms", [])),
                "official_category": official,
                "official_name": OFFICIAL_CATEGORY_NAMES[official],
            }
        return {
            "categories": categories,
            "official_categories": official_category_payload(),
        }

    @classmethod
    def _validate_import(cls, incoming: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(incoming, dict):
            raise TypeError("导入词库必须是 JSON 对象")
        if "categories" in incoming:
            unknown_top_level = set(incoming) - {"version", "categories"}
            if unknown_top_level:
                raise ValueError("导入词库顶层含未知字段")
            source = incoming["categories"]
        else:
            source = incoming
        if not isinstance(source, dict) or not source:
            raise ValueError("导入词库 categories 必须是非空对象")
        validated: dict[str, dict[str, Any]] = {}
        seen: dict[str, set[str]] = {}
        for raw_category, raw_item in source.items():
            category = resolve_keyword_category(cls._category_value(raw_category))
            if isinstance(raw_item, list):
                terms = raw_item
                score = 0.7
            elif isinstance(raw_item, dict):
                unknown = set(raw_item) - {"score", "terms"}
                if unknown:
                    raise ValueError(f"词库类别 {raw_category} 含未知字段")
                if "terms" not in raw_item:
                    raise ValueError(f"词库类别 {raw_category} 缺少 terms")
                terms = raw_item["terms"]
                score = cls._score_value(raw_item.get("score"), 0.7)
            else:
                raise TypeError(f"词库类别 {raw_category} 必须是对象或数组")
            if not isinstance(terms, list):
                raise TypeError(f"词库类别 {raw_category} 的 terms 必须是数组")
            item = validated.setdefault(
                category,
                {"score": score, "terms": [], "duplicates": 0},
            )
            keys = seen.setdefault(category, set())
            for raw_term in terms:
                term = cls._term_value(raw_term)
                key = cls._term_key(term)
                if key in keys:
                    item["duplicates"] += 1
                    continue
                keys.add(key)
                item["terms"].append(term)
        return validated

    @staticmethod
    def _categories_value(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise TypeError("当前词库顶层必须是对象")
        categories = data.setdefault("categories", {})
        if not isinstance(categories, dict):
            raise TypeError("当前词库 categories 必须是对象")
        return categories

    @classmethod
    def _category_item(cls, category: str, item: Any) -> None:
        if not isinstance(item, dict):
            raise TypeError(f"当前词库类别 {category} 必须是对象")
        cls._score_value(item.get("score"), 0.7)
        terms = item.get("terms")
        if not isinstance(terms, list):
            raise TypeError(f"当前词库类别 {category} 的 terms 必须是数组")
        for term in terms:
            cls._term_value(term)

    @staticmethod
    def _category_value(category: Any) -> str:
        if not isinstance(category, str) or not category.strip():
            raise ValueError("词库类别不能为空")
        return category

    @classmethod
    def _term_value(cls, term: Any) -> str:
        if not isinstance(term, str):
            raise TypeError("词条必须是字符串")
        value = term.strip()
        if not value:
            raise ValueError("词条不能为空")
        if len(value) > cls.MAX_TERM_CHARS:
            raise ValueError(f"词条不能超过 {cls.MAX_TERM_CHARS} 个字符")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("词条不能包含控制字符")
        if not cls._term_key(value):
            raise ValueError("词条规范化后不能为空")
        return value

    @staticmethod
    def _term_key(term: str) -> str:
        return normalize(term).compact.casefold()

    @staticmethod
    def _score_value(score: Any, default: float) -> float:
        if score is None:
            return default
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise TypeError("词库分数必须是数字")
        value = float(score)
        if not 0 < value <= 1:
            raise ValueError("词库分数必须大于 0 且不超过 1")
        return value


def compile_rule(rule: dict[str, Any]) -> re.Pattern[str] | None:
    try:
        return re.compile(str(rule["pattern"]), re.IGNORECASE | re.UNICODE)
    except (KeyError, re.error):
        return None
