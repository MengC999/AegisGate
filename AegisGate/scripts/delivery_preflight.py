#!/usr/bin/env python3
"""Read-only preflight for a future AegisGate staging/delivery directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


# Running the preflight must not create cache files that violate its own boundary.
sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import build_manifest  # noqa: E402


REQUIRED_PATHS = (
    "src",
    "web",
    "config",
    "data",
    "models/official_four_onnx_v2",
    "models/official_four_onnx_v1",
    "data/semantic_classifier_v1",
    "data/semantic_classifier_v2",
    "tests",
    "docs",
    "reports",
    "screenshots",
    "README.md",
    ".env.example",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "VERSION",
    "requirements.txt",
    "requirements-models.txt",
    "requirements-dev.txt",
    "requirements-training.txt",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SBOM.json",
    "models/downloads.json",
    ".github/workflows/ci.yml",
)
TEXT_SUFFIXES = {
    ".py",
    ".json",
    ".jsonl",
    ".md",
    ".html",
    ".js",
    ".css",
    ".txt",
    ".bat",
    ".csv",
    ".sha256",
    ".example",
    ".yml",
    ".yaml",
    ".ps1",
    ".svg",
    ".cjs",
}
PLACEHOLDER_RE = re.compile(
    r"(?i)(test|fake|dummy|example|marker|redacted|placeholder|your|"
    r"from-environment|你的|填入|示例)"
)
SECRET_PATTERNS = (
    ("deepseek_key", re.compile(r"(?i)sk-[A-Za-z0-9_-]{16,}")),
    ("bearer_value", re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]{16,}")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|auth[_-]?token|access[_-]?token|secret|password)"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9._-]{24,}"
        ),
    ),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("credential_url", re.compile(r"https?://[^\s/:]+:[^\s/@]+@")),
)


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _safe_paths(root: Path) -> Iterable[Path]:
    """Yield only files that the final manifest/package is allowed to read."""
    for path in build_manifest._files(root):
        relative = path.relative_to(root)
        if not build_manifest._excluded_file(relative):
            yield path


def _forbidden_paths(root: Path) -> list[str]:
    """Find excluded material using metadata only; never open its contents."""
    found: list[str] = []

    def visit(directory: Path) -> None:
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
        except OSError:
            return
        for path in children:
            relative = path.relative_to(root)
            if path.is_symlink():
                found.append(relative.as_posix())
                continue
            if path.is_dir():
                # Repository metadata is expected after cloning and is never packaged.
                if relative.as_posix() == ".git":
                    continue
                if build_manifest._excluded_directory(path.name):
                    found.append(relative.as_posix())
                    continue
                visit(path)
                continue
            lowered = path.name.casefold()
            if relative.as_posix() == ".git":
                continue
            if lowered == ".env" or (lowered.startswith(".env.") and lowered != ".env.example"):
                found.append(relative.as_posix())
            elif relative.parts and relative.parts[0] == "runtime" and relative.as_posix() != "runtime/README.md":
                found.append(relative.as_posix())
            elif path.suffix.casefold() in {".pem", ".key", ".p12", ".pfx"}:
                found.append(relative.as_posix())

    visit(root)
    return sorted(found)


def _secret_hits(root: Path) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for path in _safe_paths(root):
        if path.suffix.casefold() not in TEXT_SUFFIXES:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        for line_number, line in enumerate(lines, start=1):
            for kind, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    if PLACEHOLDER_RE.search(match.group(0)):
                        continue
                    hits.append(
                        {
                            "path": _relative(root, path),
                            "line": line_number,
                            "kind": kind,
                        }
                    )
    return hits


def _model_hash_status(root: Path) -> dict[str, Any]:
    checked = 0
    missing_weights: list[str] = []
    try:
        downloads = json.loads((root / "models/downloads.json").read_text(encoding="utf-8"))
        for version in ("v1", "v2"):
            record = downloads["models"][version]
            model_dir = root / "models" / f"official_four_onnx_{version}"
            checksum_file = model_dir / "SHA256SUMS"
            if not checksum_file.is_file():
                return {"status": "missing", "checked": checked}
            expected: dict[str, str] = {}
            for line in checksum_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                digest, relative = line.split("  ", 1)
                if (relative in expected or "/" in relative or "\\" in relative
                        or relative in {".", ".."} or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                    return {"status": "invalid", "checked": checked}
                expected[relative] = digest
            if expected.get("model.onnx") != record["sha256"]:
                return {"status": "invalid", "checked": checked}
            if record["path"] != f"models/official_four_onnx_{version}/model.onnx":
                return {"status": "invalid", "checked": checked}
            required = {"model.onnx", "vocab.txt", "labels.json", "tokenizer_config.json",
                        "model_card.md", "SOURCE.json", "LICENSE.apache-2.0.txt", "training_summary.json"}
            if not required.issubset(expected):
                return {"status": "invalid", "checked": checked}
            for relative, digest in expected.items():
                path = model_dir / relative
                if relative == "model.onnx" and not path.exists():
                    missing_weights.append(version)
                    continue
                if not path.is_file() or path.is_symlink():
                    return {"status": "invalid", "checked": checked}
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    return {"status": "invalid", "checked": checked}
                if relative == "model.onnx" and path.stat().st_size != record["bytes"]:
                    return {"status": "invalid", "checked": checked}
                checked += 1
    except (OSError, ValueError, KeyError, TypeError):
        return {"status": "invalid", "checked": checked}
    return {"status": "external" if missing_weights else "ready", "checked": checked,
            "missing_weights": missing_weights}


def _manifest_status(root: Path) -> dict[str, Any]:
    manifest = root / "MANIFEST.sha256"
    if not manifest.is_file():
        return {"status": "missing"}
    expected: dict[str, str] = {}
    try:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if line.strip():
                digest, relative = line.split("  ", 1)
                expected[relative] = digest
        actual = {
            _relative(root, path): build_manifest.file_digest(path)
            for path in _safe_paths(root)
        }
    except (OSError, ValueError):
        return {"status": "invalid"}
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    changed = sorted(path for path in set(expected) & set(actual) if expected[path] != actual[path])
    return {
        "status": "ready" if not (missing or unexpected or changed) else "stale",
        "entries": len(actual),
        "missing": missing[:20],
        "unexpected": unexpected[:20],
        "changed": changed[:20],
    }


def run(root: Path, require_manifest: bool = False) -> dict[str, Any]:
    root = root.resolve()
    missing = [relative for relative in REQUIRED_PATHS if not (root / relative).exists()]
    forbidden = _forbidden_paths(root)
    secret_hits = _secret_hits(root)
    safe = list(_safe_paths(root))
    manifest = _manifest_status(root)
    if require_manifest and manifest["status"] != "ready":
        manifest_failure = True
    else:
        manifest_failure = False
    models = _model_hash_status(root)
    failed = bool(missing or forbidden or secret_hits or manifest_failure or models["status"] in {"invalid", "missing"})
    return {
        "status": "fail" if failed else "pass",
        "root": str(root),
        "required_missing": missing,
        "forbidden_paths": forbidden,
        "secret_hits": secret_hits,
        "safe_file_count": len(safe),
        "safe_bytes": sum(path.stat().st_size for path in safe),
        "model_assets": models,
        "manifest": manifest,
        "manifest_required": require_manifest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="只读检查最终交付 staging 边界")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--require-manifest", action="store_true")
    parser.add_argument("--strict", action="store_true", help="发现任何边界问题时返回非零")
    args = parser.parse_args()
    result = run(args.root, require_manifest=args.require_manifest)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if args.strict and result["status"] != "pass" else 0


if __name__ == "__main__":
    raise SystemExit(main())
