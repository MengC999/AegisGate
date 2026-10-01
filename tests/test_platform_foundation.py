from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.platform_support import collect_environment, missing_dependency_files  # noqa: E402
from scripts.platform_acceptance import _evaluation_summary  # noqa: E402


class PlatformFoundationTests(unittest.TestCase):
    def test_sources_parse_with_python_3_10_grammar(self) -> None:
        files = sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "scripts").rglob("*.py"))
        files += sorted((ROOT / "tests").rglob("*.py"))
        for path in files:
            source = path.read_text(encoding="utf-8-sig")
            ast.parse(source, filename=str(path), feature_version=10)

    def test_environment_records_baseline_platform_and_dependencies(self) -> None:
        environment = collect_environment(ROOT)
        self.assertEqual(environment["python"]["baseline"], "3.12")
        self.assertEqual(environment["python"]["compatibility_target"], "3.10-3.13")
        self.assertTrue(environment["system"]["name"])
        self.assertTrue(environment["system"]["cpu_architecture"])
        self.assertEqual(
            set(environment["dependencies"]),
            {"runtime", "development", "local_model_runtime", "training"},
        )
        self.assertTrue(environment["dependencies"]["local_model_runtime"]["installed_by_default"])
        self.assertFalse(environment["dependencies"]["training"]["installed_by_default"])
        self.assertEqual(environment["local_model_runtime"]["numpy_version"], "2.2.6")
        self.assertEqual(environment["local_model_runtime"]["onnxruntime_version"], "1.23.2")
        self.assertTrue(environment["local_model_runtime"]["cpu_execution_provider"])
        self.assertEqual(missing_dependency_files(environment), [])

    def test_core_python_has_no_windows_only_path_or_shell_dependency(self) -> None:
        files = sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "scripts").rglob("*.py"))
        forbidden = {
            "fixed drive path": re.compile(r"(?i)(?<![a-z])[a-z]:[\\/]") ,
            "os.path API": re.compile(r"\bos\.path\b"),
            "PowerShell dependency": re.compile(r"(?i)\bpowershell(?:\.exe)?\b"),
            "cmd dependency": re.compile(r"(?i)\bcmd\.exe\b"),
            "Python launcher dependency": re.compile(r"(?i)\bpy\s+-3(?:\.\d+)?\b"),
        }
        violations: list[str] = []
        for path in files:
            source = path.read_text(encoding="utf-8-sig")
            for label, pattern in forbidden.items():
                if pattern.search(source):
                    violations.append(f"{path.relative_to(ROOT).as_posix()}: {label}")
        self.assertEqual(violations, [])

    def test_python_child_processes_use_active_interpreter(self) -> None:
        for relative in ("scripts/acceptance.py", "scripts/platform_acceptance.py"):
            source = (ROOT / relative).read_text(encoding="utf-8-sig")
            self.assertIn("sys.executable", source)
            self.assertIn("subprocess.run", source)

    def test_default_acceptance_keeps_auxiliary_model_read_only(self) -> None:
        source = (ROOT / "scripts/acceptance.py").read_text(encoding="utf-8-sig")
        self.assertIn("--refresh-auxiliary-model", source)
        self.assertIn("默认验收不修改模型文件", source)
        self.assertIn("if args.refresh_auxiliary_model", source)

    def test_windows_shortcuts_delegate_to_portable_entrypoints(self) -> None:
        launcher = (ROOT / "启动演示.bat").read_text(encoding="utf-8-sig")
        acceptance = (ROOT / "一键验收.bat").read_text(encoding="utf-8-sig")
        self.assertIn("python scripts/launch_demo.py", launcher)
        self.assertIn("python scripts/platform_acceptance.py --strict-baseline", acceptance)
        self.assertNotIn("py -3", launcher.lower())
        self.assertNotIn("py -3", acceptance.lower())

    def test_deepseek_smoke_requires_explicit_environment_key(self) -> None:
        environment = os.environ.copy()
        environment.pop("DEEPSEEK_API_KEY", None)
        completed = subprocess.run(
            [sys.executable, "scripts/deepseek_smoke_test.py"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            env=environment,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("status=missing_api_key", completed.stdout)

    def test_platform_acceptance_summarizes_v2_model_report(self) -> None:
        summary = _evaluation_summary({"exit_code": 0})
        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["evaluation_purpose"], "post_fix_regression")
        self.assertFalse(summary["independent_holdout"])
        self.assertEqual(summary["dataset_id"], "aegisgate-official-four-v2")
        self.assertEqual(summary["dataset_version"], "2.0.0")
        self.assertEqual(summary["test_samples"], 250)
        self.assertEqual(summary["execution_provider"], "CPUExecutionProvider")
        self.assertEqual(summary["model_status"]["status"], "ready")
        self.assertIn("macro_f1", summary["raw_classifier"])
        self.assertIn("binary", summary["thresholded_evidence"])
        self.assertIn("binary", summary["end_to_end_gateway"])


if __name__ == "__main__":
    unittest.main()
