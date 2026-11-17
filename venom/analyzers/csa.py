import json
import os
import plistlib
import tempfile

from .base import Analyzer

CWE_MAP = {
    "core.NullDereference": 476,
    "core.DivideZero": 369,
    "core.StackAddressEscape": 562,
    "core.UndefinedBinaryOperatorResult": 682,
    "core.uninitialized.Assign": 457,
    "core.uninitialized.Branch": 457,
    "core.uninitialized.UndefReturn": 457,
    "unix.Malloc": 401,
    "unix.MallocSizeof": 131,
    "unix.MismatchedDeallocator": 762,
    "unix.cstring.NullArg": 476,
    "unix.cstring.BadSizeArg": 120,
    "alpha.security.ArrayBound": 120,
    "alpha.security.ArrayBoundV2": 120,
    "alpha.security.ReturnPtrRange": 466,
    "alpha.security.taint.TaintPropagation": 20,
    "alpha.core.CastSize": 704,
    "alpha.core.CastToStruct": 704,
    "alpha.unix.SimpleStream": 775,
    "alpha.unix.Stream": 775,
    "security.insecureAPI.gets": 242,
    "security.insecureAPI.strcpy": 120,
    "security.FloatLoopCounter": 681,
    "deadcode.DeadStores": 561,
    "cplusplus.NewDelete": 415,
    "cplusplus.NewDeleteLeaks": 401,
    "core.CallAndMessage": 457,
    "security.insecureAPI.DeprecatedOrUnsafeBufferHandling": 120,
    "security.insecureAPI.mkstemp": 377,
    "security.insecureAPI.mktemp": 377,
    "security.insecureAPI.rand": 338,
    "security.insecureAPI.vfork": 242,
}

CONFIDENCE_HIGH = {
    "core.NullDereference", "unix.Malloc", "cplusplus.NewDelete",
    "core.DivideZero", "core.StackAddressEscape",
}


class ClangStaticAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "clang-sa"

    @property
    def version(self) -> str:
        for cmd in ("clang-21", "clang"):
            if self.which(cmd):
                try:
                    r = self.run([cmd, "--version"])
                    return r.stdout.splitlines()[0]
                except Exception:
                    pass
        return "n/a"

    def _clang_cmd(self) -> str | None:
        for c in ("clang-21", "clang"):
            if self.which(c):
                return c
        return None

    def is_available(self) -> bool:
        return self._clang_cmd() is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        clang = self._clang_cmd()
        if not clang:
            return []

        files = self.collect_files(target_path)
        if not files:
            return []

        findings: list[dict] = []
        for fpath in files:
            try:
                findings.extend(self._analyze_file(clang, fpath))
            except Exception:
                continue
        return findings

    def _analyze_file(self, clang: str, fpath: str) -> list[dict]:
        ext = os.path.splitext(fpath)[1].lower()
        lang = "c++" if ext in self.CPP_EXTENSIONS else "c"

        r = self.run([
            clang, "--analyze",
            "-x", lang,
            "-Xanalyzer", "-analyzer-checker=core,unix,security,deadcode,cplusplus",
            fpath,
        ], timeout=120)

        return self._parse_text(r.stderr, fpath)

    def _parse_sarif(self, sarif_path: str, default_file: str) -> list[dict]:
        try:
            with open(sarif_path) as f:
                sarif = json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

        findings = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                msg = result.get("message", {}).get("text", "")
                level = result.get("level", "warning")

                fpath = default_file
                line = col = 0
                for loc in result.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    uri = art.get("uri", "")
                    if uri:
                        fpath = uri.replace("file://", "")
                    region = phys.get("region", {})
                    line = region.get("startLine", 0)
                    col = region.get("startColumn", 0)
                    break

                findings.append(self.finding(
                    file=fpath, line=line, column=col,
                    message=msg,
                    severity="error" if level == "error" else "warning",
                    cwe=CWE_MAP.get(rule_id),
                    category=rule_id,
                    confidence="high" if rule_id in CONFIDENCE_HIGH else "medium",
                ))
        return findings

    def _parse_plist(self, plist_path: str, default_file: str) -> list[dict]:
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        except Exception:
            return []

        src_files = data.get("files", [])
        findings = []
        for diag in data.get("diagnostics", []):
            desc = diag.get("description", "")
            checker = diag.get("check_name", "")
            loc = diag.get("location", {})
            file_idx = loc.get("file", 0)
            fpath = src_files[file_idx] if file_idx < len(src_files) else default_file
            line = loc.get("line", 0)
            col = loc.get("col", 0)

            findings.append(self.finding(
                file=fpath, line=line, column=col,
                message=desc,
                severity="warning",
                cwe=CWE_MAP.get(checker),
                category=checker,
                confidence="high" if checker in CONFIDENCE_HIGH else "medium",
            ))
        return findings

    _CLANG_DIAG_RE = __import__("re").compile(
        r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+"
        r"(?P<sev>warning|error|note):\s+(?P<msg>.+?)"
        r"(?:\s+\[(?P<checker>[^\]]+)\])?\s*$"
    )

    def _parse_text(self, stderr: str, default_file: str) -> list[dict]:
        findings = []
        for line in stderr.splitlines():
            m = self._CLANG_DIAG_RE.match(line)
            if not m:
                continue
            d = m.groupdict()
            if d["sev"] not in ("warning", "error"):
                continue
            checker = d.get("checker", "") or ""
            findings.append(self.finding(
                file=d["file"], line=int(d["line"]),
                column=int(d["col"]),
                message=d["msg"],
                severity=d["sev"],
                cwe=CWE_MAP.get(checker),
                category=checker,
                confidence="high" if checker in CONFIDENCE_HIGH else "medium",
            ))
        return findings
