import json
import os
import tempfile

from .base import Analyzer

CWE_MAP = {
    "boa": 120,
    "buffer-overflow-analysis": 120,
    "dbz": 369,
    "division-by-zero": 369,
    "nullity": 476,
    "null-pointer-dereference": 476,
    "uva": 457,
    "uninitialized-variable-analysis": 457,
    "sio": 190,
    "signed-int-overflow": 190,
    "uio": 190,
    "unsigned-int-overflow": 190,
    "poa": 823,
    "pointer-overflow-analysis": 823,
    "shc": 682,
    "shift-count": 682,
    "pcmp": 467,
    "pointer-comparison": 467,
    "sound": None,
    "soundness": None,
    "fca": None,
    "function-call-analysis": None,
    "prover": None,
}

SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "ok": None,
    "unreachable": None,
    "safe": None,
}

CONFIDENCE_HIGH = {"boa", "nullity", "dbz"}


class IkosAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "ikos"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["ikos", "--version"])
            return r.stdout.strip().splitlines()[0] if r.stdout else "unknown"
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("ikos") is not None

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
            out_json = os.path.join(tmpdir, "report.json")
            db_path = os.path.join(tmpdir, "output.db")

            r = self.run([
                "ikos",
                "--rm-db",
                "-d", "interval",
                "-a", "boa,dbz,nullity,uva,sio,uio,poa,shc",
                "--format", "json",
                "--output-db", db_path,
                "-o", out_json,
                fpath,
            ], timeout=300)

            if not os.path.exists(out_json):
                return self._parse_text(r.stderr, fpath)

            try:
                with open(out_json) as f:
                    report = json.load(f)
            except (json.JSONDecodeError, OSError):
                return self._parse_text(r.stderr, fpath)

            return self._parse_json(report, fpath)

    def _parse_json(self, report: dict | list, default_file: str) -> list[dict]:
        findings = []
        checks = report if isinstance(report, list) else report.get("checks", [])

        for entry in checks:
            status = entry.get("status", "")
            if status in ("ok", "unreachable", "safe"):
                continue

            kind = entry.get("check", entry.get("kind", ""))
            location = entry.get("location", {})
            file = location.get("file", default_file)
            line = location.get("line", 0)
            column = location.get("column", 0)
            message = entry.get("message", entry.get("info", kind))

            short_kind = kind.lower().split("-analysis")[0] if "-analysis" in kind else kind.lower()
            cwe = CWE_MAP.get(kind) or CWE_MAP.get(short_kind)
            sev = SEVERITY_MAP.get(status, "medium")
            if sev is None:
                continue

            findings.append(self.finding(
                file=file,
                line=line,
                column=column,
                message=message or f"IKOS {kind}: {status}",
                severity=sev,
                cwe=cwe,
                category=kind,
                confidence="high" if short_kind in CONFIDENCE_HIGH else "medium",
            ))
        return findings

    def _parse_text(self, stderr: str, default_file: str) -> list[dict]:
        import re
        findings = []
        pattern = re.compile(
            r"^(?P<file>[^:]+):(?P<line>\d+):\d+:"
            r"\s+(?P<sev>error|warning):\s+(?P<msg>.+?)$"
        )
        for line in stderr.splitlines():
            m = pattern.match(line)
            if not m:
                continue
            d = m.groupdict()
            sev = "high" if d["sev"] == "error" else "medium"
            findings.append(self.finding(
                file=d["file"],
                line=int(d["line"]),
                message=d["msg"],
                severity=sev,
                cwe=None,
                category="ikos-text",
                confidence="medium",
            ))
        return findings
