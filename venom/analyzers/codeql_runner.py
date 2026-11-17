import json
import os
import tempfile

from .base import Analyzer


class CodeQLAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "codeql"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["codeql", "version"])
            return r.stdout.strip().splitlines()[0] if r.stdout else "unknown"
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("codeql") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        target_path = os.path.abspath(target_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "codeql-db")
            sarif_path = os.path.join(tmpdir, "results.sarif")

            build_cmd = self._build_command(target_path)
            if build_cmd is None:
                return []

            r = self.run([
                "codeql", "database", "create", db_path,
                "--language=cpp",
                "--overwrite",
                f"--command={build_cmd}",
                "--source-root", target_path if os.path.isdir(target_path) else os.path.dirname(target_path),
            ], timeout=600)

            if not os.path.isdir(db_path):
                return []

            suite = self._find_suite()
            r = self.run([
                "codeql", "database", "analyze", db_path,
                "--format=sarif-latest",
                f"--output={sarif_path}",
                "--threads=0",
                suite,
            ], timeout=600)

            if not os.path.exists(sarif_path):
                return []

            return self._parse_sarif(sarif_path, target_path)

    def _build_command(self, target_path: str) -> str | None:
        if os.path.isfile(target_path):
            ext = os.path.splitext(target_path)[1].lower()
            compiler = "g++" if ext in self.CPP_EXTENSIONS else "gcc"
            return f"{compiler} -c {target_path} -o /dev/null"

        for makefile in ("Makefile", "makefile", "GNUmakefile"):
            if os.path.exists(os.path.join(target_path, makefile)):
                return "make -j$(nproc)"

        files = self.collect_files(target_path)
        if not files:
            return None

        cmds = []
        for fpath in files:
            ext = os.path.splitext(fpath)[1].lower()
            compiler = "g++" if ext in self.CPP_EXTENSIONS else "gcc"
            cmds.append(f"{compiler} -c {fpath} -o /dev/null")
        return " && ".join(cmds)

    def _find_suite(self) -> str:
        for suite in (
            "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls",
            "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
            "codeql/cpp-queries",
        ):
            return suite
        return "codeql/cpp-queries"

    def _parse_sarif(self, sarif_path: str, default_target: str) -> list[dict]:
        try:
            with open(sarif_path) as f:
                sarif = json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

        findings = []
        for run in sarif.get("runs", []):
            rules = {}
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                cwe_ids = []
                for tag in rule.get("properties", {}).get("tags", []):
                    if tag.startswith("external/cwe/cwe-"):
                        try:
                            cwe_ids.append(int(tag.split("cwe-")[1]))
                        except (IndexError, ValueError):
                            pass
                rules[rule_id] = {
                    "cwe": cwe_ids[0] if cwe_ids else None,
                    "name": rule.get("shortDescription", {}).get("text", rule_id),
                    "severity": rule.get("defaultConfiguration", {}).get("level", "warning"),
                }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule_info = rules.get(rule_id, {})
                msg = result.get("message", {}).get("text", "")
                level = result.get("level", rule_info.get("severity", "warning"))

                fpath = default_target
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

                cwe = rule_info.get("cwe")
                if not cwe:
                    for tag in result.get("properties", {}).get("tags", []):
                        if tag.startswith("external/cwe/cwe-"):
                            try:
                                cwe = int(tag.split("cwe-")[1])
                            except (IndexError, ValueError):
                                pass
                            break

                sev_map = {"error": "high", "warning": "medium", "note": "low"}
                findings.append(self.finding(
                    file=fpath,
                    line=line,
                    column=col,
                    message=msg,
                    severity=sev_map.get(level, "medium"),
                    cwe=cwe,
                    category=rule_id,
                    confidence="high" if level == "error" else "medium",
                ))
        return findings
