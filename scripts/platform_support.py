#!/usr/bin/env python3
"""Shared, standard-library-only platform inspection helpers."""

from __future__ import annotations

import os
import platform
import sys
from importlib import import_module, metadata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASELINE_PYTHON = (3, 12)
COMPATIBILITY_MIN = (3, 10)
COMPATIBILITY_MAX = (3, 13)
MINIMUM_RUNTIME = (3, 10)
DEPENDENCY_FILES = {
    "runtime": ("requirements.txt", True),
    "development": ("requirements-dev.txt", False),
    "local_model_runtime": ("requirements-models.txt", True),
    "training": ("requirements-training.txt", False),
}


def _version_text(version: tuple[int, int]) -> str:
    return ".".join(str(part) for part in version)


def _requirement_entries(path: Path) -> list[str]:
    if not path.is_file():
        return []
    entries: list[str] = []
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def _installed_version(distribution: str) -> str | None:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None


def _local_model_runtime() -> dict[str, Any]:
    result: dict[str, Any] = {
        "numpy_version": _installed_version("numpy"),
        "onnxruntime_version": _installed_version("onnxruntime"),
        "available_providers": [],
        "cpu_execution_provider": False,
    }
    try:
        onnxruntime = import_module("onnxruntime")
        providers = [str(item) for item in onnxruntime.get_available_providers()]
    except (ImportError, OSError, AttributeError):
        return result
    result["available_providers"] = providers
    result["cpu_execution_provider"] = "CPUExecutionProvider" in providers
    return result


def collect_environment(root: Path) -> dict[str, Any]:
    """Return facts needed to distinguish a real baseline run from compatibility evidence."""
    version = sys.version_info[:2]
    baseline_match = version == BASELINE_PYTHON
    compatibility_target = COMPATIBILITY_MIN <= version <= COMPATIBILITY_MAX
    runtime_supported = version >= MINIMUM_RUNTIME
    if baseline_match:
        python_status = "baseline"
    elif compatibility_target:
        python_status = "compatible_target"
    elif runtime_supported:
        python_status = "outside_tested_target"
    else:
        python_status = "unsupported"

    dependencies: dict[str, Any] = {}
    for group, (relative, installed_by_default) in DEPENDENCY_FILES.items():
        path = root / relative
        dependencies[group] = {
            "file": path.relative_to(root).as_posix(),
            "present": path.is_file(),
            "entries": _requirement_entries(path),
            "installed_by_default": installed_by_default,
        }

    return {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "project_root": str(root.resolve()),
        "system": {
            "name": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "cpu_architecture": platform.machine() or "unknown",
            "processor": platform.processor() or "unknown",
            "logical_cpu_count": os.cpu_count(),
        },
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "baseline": _version_text(BASELINE_PYTHON),
            "compatibility_target": (
                f"{_version_text(COMPATIBILITY_MIN)}-"
                f"{_version_text(COMPATIBILITY_MAX)}"
            ),
            "minimum_runtime": _version_text(MINIMUM_RUNTIME),
            "baseline_match": baseline_match,
            "within_compatibility_target": compatibility_target,
            "runtime_supported": runtime_supported,
            "status": python_status,
        },
        "dependencies": dependencies,
        "local_model_runtime": _local_model_runtime(),
    }


def missing_dependency_files(environment: dict[str, Any]) -> list[str]:
    return [
        str(item["file"])
        for item in environment["dependencies"].values()
        if not item["present"]
    ]
