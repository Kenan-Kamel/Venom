import re

from .base import Analyzer

WARN_RE = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+"
    r"(?P<sev>warning|error):\s+(?P<msg>.+)$"
)

CWE_KEYWORDS = {
    "null": 476,
    "uninitialized": 457,
    "overflow": 190,
    "leak": 401,
    "out of bounds": 120,
    "use after": 416,
    "cast": 704,
    "incompatible": 704,
    "shadow": 561,
}


class SparseAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "sparse"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["sparse", "--version"])
            return (r.stdout or r.stderr).strip() or "unknown"
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("sparse") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        files = self.collect_files(target_path, self.C_EXTENSIONS)
        if not files:
            return []

        findings: list[dict] = []
        for fpath in files:
            try:
                r = self.run(["sparse", fpath], timeout=60)
                findings.extend(self._parse(r.stderr))
            except Exception:
                continue
        return findings

    def _parse(self, stderr: str) -> list[dict]:
        findings = []
        for line in stderr.splitlines():
            m = WARN_RE.match(line.strip())
            if not m:
                continue

            msg = m.group("msg")
            cwe_val = None
            msg_lower = msg.lower()
            for kw, cwe in CWE_KEYWORDS.items():
                if kw in msg_lower:
                    cwe_val = cwe
                    break

            findings.append(self.finding(
                file=m.group("file"),
                line=int(m.group("line")),
                column=int(m.group("col")),
                message=msg,
                severity=m.group("sev"),
                cwe=cwe_val,
                category="sparse",
                confidence="low",
            ))
        return findings
