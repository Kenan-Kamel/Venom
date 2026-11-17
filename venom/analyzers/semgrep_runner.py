import json

from .base import Analyzer

SEVERITY_MAP = {
    "ERROR": "error",
    "WARNING": "warning",
    "INFO": "info",
}


class SemgrepAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["semgrep", "--version"])
            return r.stdout.strip()
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("semgrep") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        configs = [
            "p/c-cpp-security-audit",
            "p/c-lang-security",
            "p/security-audit",
            "auto",
        ]
        all_results = []
        for config in configs:
            try:
                r = self.run([
                    "semgrep",
                    f"--config={config}",
                    "--json", "--quiet",
                    "--no-git-ignore",
                    target_path,
                ], timeout=300)
                try:
                    data = json.loads(r.stdout)
                    all_results.extend(data.get("results", []))
                except (json.JSONDecodeError, ValueError):
                    pass
            except Exception:
                continue

        seen = set()
        results_dedup = []
        for r in all_results:
            key = (r.get("path", ""), r.get("start", {}).get("line", 0), r.get("check_id", ""))
            if key not in seen:
                seen.add(key)
                results_dedup.append(r)

        findings = []
        for result in results_dedup:
            check_id = result.get("check_id", "")
            msg = result.get("extra", {}).get("message", "")
            sev = result.get("extra", {}).get("severity", "WARNING")
            fpath = result.get("path", "")
            start = result.get("start", {})
            line = start.get("line", 0)
            col = start.get("col", 0)

            metadata = result.get("extra", {}).get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe_val = None
            if isinstance(cwe_list, list) and cwe_list:
                cwe_str = cwe_list[0] if isinstance(cwe_list[0], str) else str(cwe_list[0])
                try:
                    cwe_val = int(cwe_str.split("-")[1].split(":")[0])
                except (IndexError, ValueError):
                    pass
            elif isinstance(cwe_list, str):
                try:
                    cwe_val = int(cwe_list.split("-")[1].split(":")[0])
                except (IndexError, ValueError):
                    pass

            sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
            confidence = metadata.get("confidence", "MEDIUM").lower()
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"

            findings.append(self.finding(
                file=fpath, line=line, column=col,
                message=msg,
                severity=sev_map.get(sev, "medium"),
                cwe=cwe_val,
                category=check_id,
                confidence=confidence,
            ))

        return findings
