import json
import os
import tempfile

from .base import Analyzer

CWE_MAP = {
    "NULL_DEREFERENCE": 476,
    "NULLPTR_DEREFERENCE": 476,
    "USE_AFTER_FREE": 416,
    "USE_AFTER_DELETE": 416,
    "USE_AFTER_LIFETIME": 416,
    "BUFFER_OVERRUN_L1": 120,
    "BUFFER_OVERRUN_L2": 120,
    "BUFFER_OVERRUN_L3": 120,
    "BUFFER_OVERRUN_L4": 120,
    "BUFFER_OVERRUN_L5": 120,
    "BUFFER_OVERRUN_U5": 120,
    "BUFFER_OVERRUN_S2": 120,
    "MEMORY_LEAK": 401,
    "PULSE_MEMORY_LEAK": 401,
    "RESOURCE_LEAK": 775,
    "PULSE_RESOURCE_LEAK": 775,
    "DEAD_STORE": 561,
    "UNINITIALIZED_VALUE": 457,
    "INFERBO_ALLOC_MAY_BE_BIG": 770,
    "INFERBO_ALLOC_IS_BIG": 770,
    "THREAD_SAFETY_violation": 362,
    "STARVATION": 667,
    "DEADLOCK": 667,
    "INTEGER_OVERFLOW_L1": 190,
    "INTEGER_OVERFLOW_L2": 190,
    "INTEGER_OVERFLOW_L5": 190,
    "INTEGER_OVERFLOW_U5": 190,
    "STACK_VARIABLE_ADDRESS_ESCAPE": 562,
    "DIVIDE_BY_ZERO": 369,
}

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "ADVICE": "low",
}

CONFIDENCE_HIGH = {
    "NULL_DEREFERENCE", "NULLPTR_DEREFERENCE",
    "USE_AFTER_FREE", "USE_AFTER_DELETE", "USE_AFTER_LIFETIME",
    "BUFFER_OVERRUN_L1", "BUFFER_OVERRUN_L2",
    "DIVIDE_BY_ZERO", "DEADLOCK",
}


class InferAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "infer"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["infer", "--version"])
            return r.stdout.strip().splitlines()[0] if r.stdout else "unknown"
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("infer") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        files = self.collect_files(target_path, self.C_EXTENSIONS | {".cpp", ".cc", ".cxx"})
        if not files:
            return []

        findings: list[dict] = []
        for fpath in files:
            try:
                findings.extend(self._analyze_file(fpath))
            except Exception:
                continue
        return findings

    def _analyze_file(self, fpath: str) -> list[dict]:
        ext = os.path.splitext(fpath)[1].lower()
        compiler = "g++" if ext in (".cpp", ".cc", ".cxx") else "gcc"
        parent_dir = os.path.dirname(fpath)
        grandparent_dir = os.path.dirname(parent_dir)

        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = os.path.join(tmpdir, "infer-out")
            r = self.run([
                "infer", "run",
                "--pulse", "--bufferoverrun", "--linters",
                "--no-progress-bar", "--quiet",
                "--results-dir", results_dir,
                "--", compiler, "-c", "-w",
                "-I", parent_dir, "-I", grandparent_dir,
                fpath, "-o", "/dev/null",
            ], timeout=120)

            report_path = os.path.join(results_dir, "report.json")
            if not os.path.exists(report_path):
                return []

            try:
                with open(report_path) as f:
                    report = json.load(f)
            except (json.JSONDecodeError, OSError):
                return []

            return self._parse_report(report, fpath)

    def _parse_report(self, report: list, default_file: str) -> list[dict]:
        findings = []
        for entry in report:
            bug_type = entry.get("bug_type", "")
            file = entry.get("file", default_file)
            line = entry.get("line", 0)
            column = entry.get("column", 0)
            qualifier = entry.get("qualifier", "")
            severity = entry.get("severity", "WARNING")
            bug_type_hum = entry.get("bug_type_hum", bug_type)

            message = qualifier or bug_type_hum

            findings.append(self.finding(
                file=file,
                line=line,
                column=column,
                message=message,
                severity=SEVERITY_MAP.get(severity, "medium"),
                cwe=CWE_MAP.get(bug_type),
                category=bug_type,
                confidence="high" if bug_type in CONFIDENCE_HIGH else "medium",
            ))
        return findings
