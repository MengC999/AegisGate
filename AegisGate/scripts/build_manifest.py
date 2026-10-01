#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRECTORIES = {
    "_guide_render",
    "_report_qa_final",
    "_report_qa_final_word",
    "_report_qa_original",
    "__pycache__",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "logs",
    "outputs",
    ".github-cache",
    "node_modules",
    "build",
    "dist",
    ".idea",
    ".vscode",
    "htmlcov",
    "patent",
    "patent_eval",
    "tmp_template",
}
EXCLUDED_NAMES = {"MANIFEST.sha256", ".DS_Store", "Thumbs.db", ".git", ".coverage"}
EXCLUDED_SUFFIXES = {
    ".pyc", ".pyo", ".tmp", ".swp", ".zip", ".onnx", ".log", ".db",
    ".pem", ".key", ".p12", ".pfx", ".gguf", ".safetensors",
    ".docx", ".pptx", ".jpg", ".jpeg",
}
PUBLIC_REPORTS = {
    "README.md",
    "semantic_model_evaluation_v2.json",
    "semantic_model_evaluation_v2_regression.json",
    "e2e_gateway_holdout_v1.json",
    "semantic_gateway_false_positive_diagnostics.json",
    "gateway_fpr_fix_summary.json",
}


def _excluded_directory(name: str) -> bool:
    lowered = name.casefold()
    return (
        lowered in EXCLUDED_DIRECTORIES
        or lowered.startswith("_report_qa_")
        or lowered.startswith("render_")
        or lowered in {"venv", "env"}
        or lowered.startswith(".venv")
    )


def _excluded_file(relative: Path) -> bool:
    name = relative.name
    lowered = name.casefold()
    secret_environment = lowered == ".env" or (
        lowered.startswith(".env.") and lowered != ".env.example"
    )
    runtime_data = relative.parts[0].casefold() == "runtime" and relative.as_posix() != "runtime/README.md"
    private_report = relative.parts[0].casefold() == "reports" and (
        len(relative.parts) != 2 or name not in PUBLIC_REPORTS
    )
    return (
        name in EXCLUDED_NAMES
        or relative.suffix.casefold() in EXCLUDED_SUFFIXES
        or secret_environment
        or runtime_data
        or private_report
        or any(part.casefold() in {"patent", "patent_eval"} for part in relative.parts[:-1])
        or lowered.endswith((".db-wal", ".db-shm"))
        or ".sqlite" in lowered
    )


def file_digest(path: Path) -> str:
    """Hash BAT files with CRLF on every platform; keep sealed assets byte-exact."""
    payload = path.read_bytes()
    if path.suffix.casefold() == ".bat":
        payload = payload.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return hashlib.sha256(payload).hexdigest()


def _files(directory: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
        if path.is_symlink():
            continue
        if path.is_dir():
            if not _excluded_directory(path.name):
                files.extend(_files(path))
        elif path.is_file():
            files.append(path)
    return files


def entries() -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for path in _files(ROOT):
        relative = path.relative_to(ROOT)
        if _excluded_file(relative):
            continue
        result.append((file_digest(path), relative.as_posix()))
    return result


def build() -> int:
    lines: list[str] = []
    for digest, relative in entries():
        lines.append(f"{digest}  {relative}")
    target = ROOT / "MANIFEST.sha256"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"已写入 {len(lines)} 个文件摘要: {target}")
    return 0


def verify() -> int:
    target = ROOT / "MANIFEST.sha256"
    if not target.is_file():
        print("校验失败：MANIFEST.sha256 不存在")
        return 1
    expected: dict[str, str] = {}
    for line_number, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            digest, relative = line.split("  ", 1)
        except ValueError:
            print(f"校验失败：清单第 {line_number} 行格式错误")
            return 1
        expected[relative] = digest
    actual = {relative: digest for digest, relative in entries()}
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    changed = sorted(path for path in set(expected) & set(actual) if expected[path] != actual[path])
    if missing or unexpected or changed:
        print(f"校验失败：缺失 {len(missing)}，新增 {len(unexpected)}，变更 {len(changed)}")
        for label, values in (("缺失", missing), ("新增", unexpected), ("变更", changed)):
            for value in values[:10]:
                print(f"  {label}: {value}")
        return 1
    print(f"文件摘要校验通过：{len(actual)} 个文件")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="生成或验证 AegisGate 文件 SHA-256 清单")
    parser.add_argument("--verify", action="store_true", help="验证当前文件与清单一致")
    args = parser.parse_args()
    return verify() if args.verify else build()


if __name__ == "__main__":
    raise SystemExit(main())
