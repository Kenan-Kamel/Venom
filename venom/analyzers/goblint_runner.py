import json
import os
import re
import tempfile

from .base import Analyzer

CWE_MAP = {
    "Race": 362,
    "Deadlock": 667,
    "Assert": 617,
    "MemoryLeak": 401,
    "Overflow": 190,
    "NullDeref": 476,
    "UninitMem": 457,
    "DoubleFree": 415,
    "UseAfterFree": 416,
    "ArrayBounds": 120,
    "DivByZero": 369,
}

SEVERITY_MAP = {
    "Race": "high",
    "Deadlock": "high",
    "Assert": "medium",
    "MemoryLeak": "medium",
    "Overflow": "high",
    "NullDeref": "high",
    "UninitMem": "medium",
    "DoubleFree": "critical",
    "UseAfterFree": "critical",
    "ArrayBounds": "critical",
    "DivByZero": "medium",
}

CONFIDENCE_HIGH = {"Race", "Deadlock", "DoubleFree", "UseAfterFree"}

_WARN_RE = re.compile(
    r"\[Warning\]\[(\w+)\]\s+(.+?)\s+\((\S+):(\d+)"
)

_WARN_ALT_RE = re.compile(
    r"\[Warning\]\[(\w+)\](?:\[(\w+)\])?\s+(.+?)(?:\s+\()?(\S+\.c):(\d+)"
)


class GoblintAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "goblint"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["goblint", "--version"])
            return r.stdout.strip() or r.stderr.strip()
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("goblint") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        files = self.collect_files(target_path, self.C_EXTENSIONS)
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
        with tempfile.TemporaryDirectory() as tmpdir:
            json_out = os.path.join(tmpdir, "result.json")

            r = self.run([
                "goblint",
                "--set", "ana.activated",
                '["base","mallocWrapper","mutex","race","threadflag"]',
                "--enable", "warn.debug",
                "--set", "result", "json",
                "--set", "result.json.path", json_out,
                fpath,
            ], timeout=180)

            findings = []

            if os.path.exists(json_out):
                findings.extend(self._parse_json(json_out, fpath))

            findings.extend(self._parse_stderr(r.stderr, fpath))

            seen = set()
            deduped = []
            for f in findings:
                key = (f["file"], f["line"], f["category"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(f)

            return deduped

    def _parse_json(self, json_path: str, default_file: str) -> list[dict]:
        try:
            with open(json_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

        findings = []
        warnings = data if isinstance(data, list) else data.get("warnings", [])

        for entry in warnings:
            if not isinstance(entry, dict):
                continue

            tags = entry.get("tags", [])
            msg = entry.get("message", entry.get("text", ""))
            loc = entry.get("loc", entry.get("location", {}))

            src_file = default_file
            line = 0
            if isinstance(loc, dict):
                src_file = loc.get("file", default_file)
                line = loc.get("line", 0)

            category = tags[0] if tags else "Unknown"
            cwe = CWE_MAP.get(category)
            severity = SEVERITY_MAP.get(category, "medium")
            confidence = "high" if category in CONFIDENCE_HIGH else "medium"

            findings.append(self.finding(
                file=src_file if os.path.isabs(src_file) else os.path.abspath(src_file),
                line=line,
                message=msg,
                severity=severity,
                cwe=cwe,
                category=f"goblint:{category}",
                confidence=confidence,
            ))

        return findings

    def _parse_stderr(self, stderr: str, default_file: str) -> list[dict]:
        findings = []

        for m in _WARN_RE.finditer(stderr):
            category = m.group(1)
            msg = m.group(2).strip()
            src_file = m.group(3)
            line = int(m.group(4))

            cwe = CWE_MAP.get(category)
            severity = SEVERITY_MAP.get(category, "medium")
            confidence = "high" if category in CONFIDENCE_HIGH else "medium"

            findings.append(self.finding(
                file=src_file if os.path.isabs(src_file) else os.path.abspath(src_file),
                line=line,
                message=msg,
                severity=severity,
                cwe=cwe,
                category=f"goblint:{category}",
                confidence=confidence,
            ))

        if not findings:
            for m in _WARN_ALT_RE.finditer(stderr):
                category = m.group(1)
                sub_cat = m.group(2) or ""
                msg = m.group(3).strip()
                src_file = m.group(4)
                line = int(m.group(5))

                effective = sub_cat if sub_cat in CWE_MAP else category
                cwe = CWE_MAP.get(effective)
                severity = SEVERITY_MAP.get(effective, "medium")

                findings.append(self.finding(
                    file=src_file if os.path.isabs(src_file) else os.path.abspath(src_file),
                    line=line,
                    message=msg,
                    severity=severity,
                    cwe=cwe,
                    category=f"goblint:{effective}",
                    confidence="medium",
                ))

        return findings
