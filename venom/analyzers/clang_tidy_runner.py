import os
import re

from .base import Analyzer

CWE_MAP = {
    "bugprone-use-after-move": 416,
    "bugprone-dangling-handle": 562,
    "bugprone-undefined-memory-manipulation": 457,
    "bugprone-sizeof-expression": 131,
    "bugprone-integer-division": 190,
    "bugprone-narrowing-conversions": 681,
    "bugprone-signed-char-misuse": 195,
    "bugprone-string-integer-assignment": 704,
    "bugprone-suspicious-memory-comparison": 188,
    "bugprone-unhandled-self-assignment": 682,
    "cert-err34-c": 190,
    "cert-msc30-c": 330,
    "cert-msc50-cpp": 330,
    "cert-env33-c": 78,
    "cert-flp30-c": 681,
    "clang-analyzer-core.NullDereference": 476,
    "clang-analyzer-core.DivideZero": 369,
    "clang-analyzer-unix.Malloc": 401,
    "clang-analyzer-cplusplus.NewDelete": 415,
    "clang-analyzer-cplusplus.NewDeleteLeaks": 401,
    "clang-analyzer-security.insecureAPI.gets": 242,
    "clang-analyzer-security.insecureAPI.strcpy": 120,
}

DIAG_RE = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+"
    r"(?P<sev>warning|error):\s+(?P<msg>.+?)\s+\[(?P<check>[^\]]+)\]\s*$"
)


class ClangTidyAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "clang-tidy"

    def _cmd(self) -> str | None:
        for c in ("clang-tidy-21", "clang-tidy"):
            if self.which(c):
                return c
        return None

    @property
    def version(self) -> str:
        cmd = self._cmd()
        if not cmd:
            return "n/a"
        try:
            r = self.run([cmd, "--version"])
            for line in r.stdout.splitlines():
                if "version" in line.lower():
                    return line.strip()
        except Exception:
            pass
        return "unknown"

    def is_available(self) -> bool:
        return self._cmd() is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        cmd = self._cmd()
        if not cmd:
            return []

        files = self.collect_files(target_path)
        if not files:
            return []

        findings: list[dict] = []
        for fpath in files:
            try:
                findings.extend(self._analyze_file(cmd, fpath))
            except Exception:
                continue
        return findings

    def _analyze_file(self, cmd: str, fpath: str) -> list[dict]:
        ext = os.path.splitext(fpath)[1].lower()
        extra_arg = f"--extra-arg=-std={'c++17' if ext in self.CPP_EXTENSIONS else 'c17'}"

        checks = ",".join([
            "clang-analyzer-*",
            "-clang-analyzer-osx.*",
            "bugprone-use-after-move",
            "bugprone-dangling-handle",
            "bugprone-undefined-memory-manipulation",
            "bugprone-sizeof-expression",
            "bugprone-integer-division",
            "bugprone-narrowing-conversions",
            "bugprone-signed-char-misuse",
            "bugprone-suspicious-memory-comparison",
            "bugprone-unhandled-self-assignment",
            "bugprone-string-integer-assignment",
            "cert-err34-c",
            "cert-env33-c",
            "cert-msc30-c",
            "cert-msc50-cpp",
            "cert-flp30-c",
        ])

        r = self.run([
            cmd,
            f"--checks=-*,{checks}",
            extra_arg,
            "--quiet",
            fpath,
            "--",
        ], timeout=60)

        findings = []
        for line in (r.stdout or "").splitlines():
            m = DIAG_RE.match(line)
            if not m:
                continue
            check = m.group("check")
            findings.append(self.finding(
                file=m.group("file"),
                line=int(m.group("line")),
                column=int(m.group("col")),
                message=m.group("msg"),
                severity=m.group("sev"),
                cwe=CWE_MAP.get(check),
                category=check,
                confidence="high" if check.startswith("clang-analyzer-core") else "medium",
            ))
        return findings
