from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


def atomic_save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=path.name, suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


class ReloadableJson:
    def __init__(self, path: Path, default: Any) -> None:
        self.path = path
        self.default = default
        self._mtime_ns = -1
        self._value = default
        self._lock = threading.RLock()

    def get(self) -> Any:
        with self._lock:
            try:
                mtime_ns = self.path.stat().st_mtime_ns
            except FileNotFoundError:
                return self.default
            if mtime_ns != self._mtime_ns:
                self._value = load_json(self.path, self.default)
                self._mtime_ns = mtime_ns
            return self._value

    def invalidate(self) -> None:
        with self._lock:
            self._mtime_ns = -1
