import os
import re
import tempfile

from .base import Analyzer

CWE_MAP = {
    "NeverFree": 401,
    "PartialLeak": 401,
    "DoubleFree": 415,
    "UseAfterFree": 416,
    "FileNeverClose": 775,
    "BufferOverflow": 120,
    "NullDereference": 476,
}

SEVERITY_MAP = {
    "NeverFree": "medium",
    "PartialLeak": "medium",
    "DoubleFree": "critical",
    "UseAfterFree": "critical",
    "FileNeverClose": "medium",
    "BufferOverflow": "critical",
    "NullDereference": "high",
}

_BUG_TYPE_RE = re.compile(
    r"Bug\s+Type:\s*(\w+)"
)
_BUG_LOC_RE = re.compile(
    r"(?:Location|File):\s*(\S+)\s+(?:line|Line)\s+(\d+)"
)

_SABER_DIAG_RE = re.compile(
    r"(\S+\.(?:c|cpp|cc|h)):(\d+):\s+(\w+):\s+(.+)"
)

_LEAK_RE = re.compile(
    r"(NeverFree|PartialLeak|DoubleFree|UseAfterFree|FileNeverClose|BufferOverflow|NullDereference)"
)


class SvfSaberAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "saber-svf"

    @property
    def version(self) -> str:
        cmd = self._tool_cmd()
        if not cmd:
            return "n/a"
        try:
            r = self.run([cmd, "--version"])
            return r.stdout.strip() or r.stderr.strip() or "unknown"
        except Exception:
            return "unknown"

    def _tool_cmd(self) -> str | None:
        for c in ("saber", "wpa"):
            if self.which(c):
                return c
        return None

    def _clang_cmd(self) -> str | None:
        for c in ("clang-21", "clang"):
            if self.which(c):
                return c
        return None

    def is_available(self) -> bool:
        return self._tool_cmd() is not None and self._clang_cmd() is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        files = self.collect_files(target_path, self.C_EXTENSIONS | {".cpp", ".cc"})
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
        clang = self._clang_cmd()
        tool = self._tool_cmd()

        with tempfile.TemporaryDirectory() as tmpdir:
            ext = os.path.splitext(fpath)[1].lower()
            lang_flag = "-x"
            lang_val = "c++" if ext in (".cpp", ".cc", ".cxx") else "c"
            bc_path = os.path.join(tmpdir, "input.bc")

            r = self.run([
                clang, "-S", "-emit-llvm", "-g",
                "-fno-discard-value-names",
                lang_flag, lang_val,
                fpath, "-o", bc_path,
            ], timeout=60)

            if not os.path.exists(bc_path):
                return []

            if tool == "saber":
                return self._run_saber(tool, bc_path, fpath)
            else:
                return self._run_wpa(tool, bc_path, fpath)

    def _run_saber(self, tool: str, bc_path: str, src_file: str) -> list[dict]:
        r = self.run([
            tool,
            "-leak", "-dfree", "-fileck",
            bc_path,
        ], timeout=120)

        return self._parse_output(r.stdout + "\n" + r.stderr, src_file)

    def _run_wpa(self, tool: str, bc_path: str, src_file: str) -> list[dict]:
        r = self.run([
            tool,
            "-ander",
            "-leak", "-dfree", "-fileck",
            bc_path,
        ], timeout=120)

        return self._parse_output(r.stdout + "\n" + r.stderr, src_file)

    def _parse_output(self, output: str, default_file: str) -> list[dict]:
        findings = []
        seen = set()

        bug_type = None
        for line in output.splitlines():
            bt = _BUG_TYPE_RE.search(line)
            if bt:
                bug_type = bt.group(1)
                continue

            loc = _BUG_LOC_RE.search(line)
            if loc and bug_type:
                src_file = loc.group(1)
                line_no = int(loc.group(2))

                key = (src_file, line_no, bug_type)
                if key not in seen:
                    seen.add(key)
                    findings.append(self.finding(
                        file=src_file if os.path.isabs(src_file) else os.path.abspath(src_file),
                        line=line_no,
                        message=f"{bug_type} detected by SVF/Saber",
                        severity=SEVERITY_MAP.get(bug_type, "medium"),
                        cwe=CWE_MAP.get(bug_type),
                        category=f"saber:{bug_type}",
                        confidence="high",
                    ))
                bug_type = None
                continue

            dm = _SABER_DIAG_RE.search(line)
            if dm:
                src_file = dm.group(1)
                line_no = int(dm.group(2))
                kind = dm.group(3)
                msg = dm.group(4)

                lm = _LEAK_RE.search(msg) or _LEAK_RE.search(kind)
                cat = lm.group(1) if lm else kind

                key = (src_file, line_no, cat)
                if key not in seen:
                    seen.add(key)
                    findings.append(self.finding(
                        file=src_file if os.path.isabs(src_file) else os.path.abspath(src_file),
                        line=line_no,
                        message=msg,
                        severity=SEVERITY_MAP.get(cat, "medium"),
                        cwe=CWE_MAP.get(cat),
                        category=f"saber:{cat}",
                        confidence="high",
                    ))

        return findings
