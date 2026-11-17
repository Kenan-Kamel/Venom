"""KNighter analyzer integration — wraps the real KNighter tool
(https://github.com/ise-uiuc/KNighter).

KNighter synthesizes Clang Static Analyzer checkers from bug-fix patches
using LLMs. This runner invokes KNighter's pipeline (gen → refine → scan →
triage) against the target codebase and returns the findings in Venom's
standard format.

Requires:
  - KNighter repo at tools/KNighter (bundled)
  - Docker  OR  manual LLVM-18 + Linux kernel setup
  - An OpenAI API key (or compatible) in llm_keys.yaml
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .base import Analyzer

KNIGHTER_ROOT = Path(__file__).resolve().parent.parent.parent / "tools" / "KNighter"
KNIGHTER_SRC = KNIGHTER_ROOT / "src"


class KNighterAnalyzer(Analyzer):

    @property
    def name(self) -> str:
        return "knighter"

    @property
    def version(self) -> str:
        return "1.0-sosp25"

    def is_available(self) -> bool:
        if self._docker_available():
            return True
        if self._local_available():
            return True
        return False

    # ── public ──

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if self._docker_available():
            return self._run_docker(target_path)
        if self._local_available():
            return self._run_local(target_path)
        return []

    # ── availability checks ──

    @staticmethod
    def _docker_available() -> bool:
        if not shutil.which("docker"):
            return False
        try:
            r = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}"],
                capture_output=True, text=True, timeout=10,
            )
            images = r.stdout.strip().splitlines()
            return "knighter" in images or "knighterhub/knighter" in images
        except (subprocess.TimeoutExpired, OSError):
            return False

    @staticmethod
    def _local_available() -> bool:
        if not KNIGHTER_SRC.is_dir():
            return False
        main_py = KNIGHTER_SRC / "main.py"
        if not main_py.exists():
            return False
        config = KNIGHTER_ROOT / "config.yaml"
        keys = KNIGHTER_ROOT / "llm_keys.yaml"
        return config.exists() and keys.exists()

    # ── Docker-based execution ──

    def _run_docker(self, target_path: str) -> list[dict]:
        abs_target = os.path.abspath(target_path)
        result_dir = tempfile.mkdtemp(prefix="knighter-results-")

        image = "knighterhub/knighter"
        try:
            r = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}"],
                capture_output=True, text=True, timeout=10,
            )
            if "knighter" in r.stdout.strip().splitlines():
                image = "knighter"
        except (subprocess.TimeoutExpired, OSError):
            pass

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{abs_target}:/target:ro",
            "-v", f"{result_dir}:/results",
            image,
            "bash", "-c",
            (
                "cd /app/src && "
                "python3 main.py scan "
                "--config_file /app/config.yaml "
                "--target_dir /target "
                "--result_dir /results "
                "2>/dev/null || true"
            ),
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except (subprocess.TimeoutExpired, OSError):
            return []

        return self._collect_results(result_dir)

    # ── Local execution ──

    def _run_local(self, target_path: str) -> list[dict]:
        abs_target = os.path.abspath(target_path)
        result_dir = tempfile.mkdtemp(prefix="knighter-results-")

        env = os.environ.copy()
        env["PYTHONPATH"] = str(KNIGHTER_SRC)

        config_path = KNIGHTER_ROOT / "config.yaml"

        cmd = [
            sys.executable, str(KNIGHTER_SRC / "main.py"),
            "scan",
            f"--config_file={config_path}",
            f"--target_dir={abs_target}",
            f"--result_dir={result_dir}",
        ]

        try:
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=3600, env=env, cwd=str(KNIGHTER_SRC),
            )
        except (subprocess.TimeoutExpired, OSError):
            return []

        return self._collect_results(result_dir)

    # ── result collection ──

    def _collect_results(self, result_dir: str) -> list[dict]:
        findings = []
        result_path = Path(result_dir)

        for json_file in result_path.rglob("*.json"):
            try:
                data = json.loads(json_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            reports = data if isinstance(data, list) else data.get("reports", [])
            for report in reports:
                if not isinstance(report, dict):
                    continue
                f = self.finding(
                    file=report.get("file", ""),
                    line=int(report.get("line", 0)),
                    column=int(report.get("column", 0)),
                    message=report.get("message", report.get("description", "")),
                    severity=self._map_severity(report.get("severity", "warning")),
                    cwe=report.get("cwe"),
                    category=report.get("checker_name", "knighter-synthesized"),
                    confidence=report.get("confidence", "medium"),
                )
                findings.append(f)

        return findings

    @staticmethod
    def _map_severity(sev: str) -> str:
        sev = sev.lower()
        if sev in ("critical", "high", "error"):
            return "error"
        if sev in ("medium", "warning"):
            return "warning"
        return "note"
