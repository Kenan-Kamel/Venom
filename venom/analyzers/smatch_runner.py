import os
import re

from .base import Analyzer

_SMATCH_RE = re.compile(
    r"^(?P<file>\S+):(?P<line>\d+)\s+(?P<func>\w+)\(\)\s+"
    r"(?P<sev>warn|error|info):\s+(?P<msg>.+)$"
)

KEYWORD_CWE = [
    (re.compile(r"null\s*(pointer\s*)?deref", re.I), 476),
    (re.compile(r"use.after.free", re.I), 416),
    (re.compile(r"double.free", re.I), 415),
    (re.compile(r"buffer.over(flow|run)", re.I), 120),
    (re.compile(r"out.of.bounds", re.I), 787),
    (re.compile(r"uninitialized", re.I), 457),
    (re.compile(r"(memory|resource)\s*leak", re.I), 401),
    (re.compile(r"integer.over(flow|run)", re.I), 190),
    (re.compile(r"format\s*string", re.I), 134),
    (re.compile(r"unchecked.*(return|error)", re.I), 252),
    (re.compile(r"(divide|division).by.zero", re.I), 369),
    (re.compile(r"(signedness|signed.*unsigned)", re.I), 681),
    (re.compile(r"(race|concurrent)", re.I), 362),
    (re.compile(r"shift", re.I), 682),
    (re.compile(r"overflow", re.I), 190),
    (re.compile(r"leak", re.I), 401),
]

SEVERITY_MAP = {
    "error": "high",
    "warn": "medium",
    "info": "low",
}


class SmatchAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "smatch"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run([self._cmd(), "--version"])
            return r.stdout.strip() or r.stderr.strip().splitlines()[0] if (r.stdout or r.stderr) else "unknown"
        except Exception:
            return "unknown"

    def _cmd(self) -> str:
        for c in ("smatch", "/usr/local/bin/smatch"):
            if self.which(c):
                return c
        return "smatch"

    def is_available(self) -> bool:
        for c in ("smatch", "/usr/local/bin/smatch"):
            if self.which(c):
                return True
        return False

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        files = self.collect_files(target_path, self.C_EXTENSIONS)
        if not files:
            return []

        findings: list[dict] = []
        cmd = self._cmd()
        for fpath in files:
            try:
                findings.extend(self._analyze_file(cmd, fpath))
            except Exception:
                continue
        return findings

    def _analyze_file(self, cmd: str, fpath: str) -> list[dict]:
        r = self.run([cmd, "--two-passes", fpath], timeout=120)

        output = (r.stdout or "") + "\n" + (r.stderr or "")
        findings = []
        for line in output.splitlines():
            m = _SMATCH_RE.match(line.strip())
            if not m:
                continue

            d = m.groupdict()
            msg = d["msg"]
            cwe = self._guess_cwe(msg)
            sev = SEVERITY_MAP.get(d["sev"], "medium")

            findings.append(self.finding(
                file=d["file"],
                line=int(d["line"]),
                message=f"{d['func']}(): {msg}",
                severity=sev,
                cwe=cwe,
                category=f"smatch-{d['sev']}",
                confidence="medium",
            ))
        return findings

    @staticmethod
    def _guess_cwe(msg: str) -> int | None:
        for pattern, cwe_id in KEYWORD_CWE:
            if pattern.search(msg):
                return cwe_id
        return None
