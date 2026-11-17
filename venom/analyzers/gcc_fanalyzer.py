import json
import os
import re

from .base import Analyzer

CWE_MAP = {
    "-Wanalyzer-double-free": 415,
    "-Wanalyzer-use-after-free": 416,
    "-Wanalyzer-malloc-leak": 401,
    "-Wanalyzer-null-dereference": 476,
    "-Wanalyzer-possible-null-dereference": 476,
    "-Wanalyzer-null-argument": 476,
    "-Wanalyzer-possible-null-argument": 476,
    "-Wanalyzer-buffer-overflow": 120,
    "-Wanalyzer-out-of-bounds": 787,
    "-Wanalyzer-shift-count-negative": 682,
    "-Wanalyzer-shift-count-overflow": 682,
    "-Wanalyzer-write-to-const": 843,
    "-Wanalyzer-write-to-string-literal": 843,
    "-Wanalyzer-use-of-uninitialized-value": 457,
    "-Wanalyzer-use-of-pointer-in-stale-stack-frame": 562,
    "-Wanalyzer-exposure-through-output-file": 532,
    "-Wanalyzer-file-leak": 775,
    "-Wanalyzer-stale-setjmp-buffer": 562,
    "-Wanalyzer-tainted-array-index": 129,
    "-Wanalyzer-tainted-divisor": 369,
    "-Wanalyzer-tainted-offset": 823,
    "-Wanalyzer-tainted-size": 120,
    "-Wanalyzer-tainted-allocation-size": 789,
    "-Wanalyzer-infinite-recursion": 674,
    "-Wanalyzer-jump-through-null": 476,
    "-Wanalyzer-fd-leak": 775,
    "-Wanalyzer-fd-use-after-close": 416,
    "-Wanalyzer-fd-double-close": 415,
    "-Wanalyzer-va-list-leak": 401,
    "-Wanalyzer-deref-before-check": 476,
}

SEVERITY_MAP = {
    "error": "error",
    "warning": "warning",
    "note": "info",
}

CONFIDENCE_HIGH = {
    "-Wanalyzer-double-free",
    "-Wanalyzer-use-after-free",
    "-Wanalyzer-null-dereference",
    "-Wanalyzer-buffer-overflow",
    "-Wanalyzer-out-of-bounds",
    "-Wanalyzer-malloc-leak",
    "-Wanalyzer-file-leak",
}


class GccFanalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "gcc-fanalyzer"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["gcc", "--version"])
            return r.stdout.splitlines()[0] if r.stdout else "unknown"
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("gcc") is not None

    def _supports_sarif(self) -> bool:
        try:
            r = self.run(
                ["gcc", "-fanalyzer", "-fdiagnostics-format=sarif-stderr",
                 "-c", "-x", "c", "/dev/null", "-o", "/dev/null"],
                timeout=15,
            )
            return "unrecognized" not in r.stderr.lower()
        except Exception:
            return False

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        files = self.collect_files(target_path, self.C_EXTENSIONS | {".cpp", ".cc", ".cxx"})
        if not files:
            return []

        use_sarif = self._supports_sarif()
        findings: list[dict] = []

        for fpath in files:
            ext = os.path.splitext(fpath)[1].lower()
            compiler = "g++" if ext in (".cpp", ".cc", ".cxx") else "gcc"
            try:
                if use_sarif:
                    findings.extend(self._run_sarif(compiler, fpath))
                if not findings:
                    findings.extend(self._run_text(compiler, fpath))
            except Exception:
                continue
        return findings

    def _run_sarif(self, compiler: str, fpath: str) -> list[dict]:
        r = self.run([
            compiler, "-fanalyzer", "-fdiagnostics-format=sarif-stderr",
            "-c", "-o", "/dev/null",
            fpath,
        ], timeout=120)

        findings = []
        for line in r.stderr.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                sarif = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.extend(self._parse_sarif(sarif, fpath))

        if not findings:
            try:
                sarif = json.loads(r.stderr)
                findings.extend(self._parse_sarif(sarif, fpath))
            except (json.JSONDecodeError, ValueError):
                pass

        if not findings:
            findings.extend(self._run_text(compiler.replace("g++", "gcc").replace("gcc", compiler), fpath, stderr=r.stderr))

        return findings

    def _parse_sarif(self, sarif: dict, default_file: str) -> list[dict]:
        findings = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                msg = result.get("message", {}).get("text", "")
                level = result.get("level", "warning")
                locations = result.get("locations", [])

                fpath = default_file
                line = 0
                col = 0
                if locations:
                    loc = locations[0].get("physicalLocation", {})
                    art = loc.get("artifactLocation", {})
                    fpath = art.get("uri", default_file)
                    if fpath.startswith("file://"):
                        fpath = fpath[7:]
                    region = loc.get("region", {})
                    line = region.get("startLine", 0)
                    col = region.get("startColumn", 0)

                flag = f"-W{rule_id}" if rule_id and not rule_id.startswith("-W") else rule_id
                cwe_val = CWE_MAP.get(flag)
                if not cwe_val:
                    for prop in result.get("properties", {}).get("tags", []):
                        if prop.startswith("CWE-"):
                            try:
                                cwe_val = int(prop.split("-")[1])
                            except (IndexError, ValueError):
                                pass

                findings.append(self.finding(
                    file=fpath,
                    line=line,
                    column=col,
                    message=msg,
                    severity=SEVERITY_MAP.get(level, "warning"),
                    cwe=cwe_val,
                    category=rule_id,
                    confidence="high" if flag in CONFIDENCE_HIGH else "medium",
                ))
        return findings

    def _run_text(self, compiler: str, fpath: str, stderr: str | None = None) -> list[dict]:
        if stderr is None:
            r = self.run([
                compiler, "-fanalyzer", "-c", "-o", "/dev/null", fpath,
            ], timeout=120)
            stderr = r.stderr

        findings = []
        for raw_line in stderr.splitlines():
            parsed = self.parse_gcc_diag(raw_line)
            if not parsed:
                continue
            if parsed["sev"] == "note":
                continue
            flag = parsed.get("flag", "") or ""
            if "analyzer" not in flag and "Wanalyzer" not in flag:
                continue

            cwe_val = CWE_MAP.get(flag)
            findings.append(self.finding(
                file=parsed["file"],
                line=int(parsed["line"]),
                column=int(parsed["col"]),
                message=parsed["msg"],
                severity=SEVERITY_MAP.get(parsed["sev"], "warning"),
                cwe=cwe_val,
                category=flag,
                confidence="high" if flag in CONFIDENCE_HIGH else "medium",
            ))
        return findings
