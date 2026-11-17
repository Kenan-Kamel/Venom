import csv
import io
import json

from .base import Analyzer

CWE_MAP_KEYWORDS = {
    "buffer": 120,
    "gets": 242,
    "strcpy": 120,
    "strcat": 120,
    "sprintf": 120,
    "scanf": 120,
    "format": 134,
    "printf": 134,
    "syslog": 134,
    "race": 362,
    "tmpnam": 377,
    "tempnam": 377,
    "mktemp": 377,
    "random": 330,
    "rand": 330,
    "crypt": 327,
    "chown": 282,
    "chmod": 732,
    "access": 367,
    "umask": 732,
    "exec": 78,
    "system": 78,
    "popen": 78,
}


class FlawfinderAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "flawfinder"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["flawfinder", "--version"])
            return r.stdout.strip() or r.stderr.strip()
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("flawfinder") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        findings = self._try_sarif(target_path)
        if findings is not None:
            return findings

        return self._try_csv(target_path)

    def _try_sarif(self, target_path: str) -> list[dict] | None:
        try:
            r = self.run(["flawfinder", "--sarif", target_path], timeout=120)
        except Exception:
            return None

        if r.returncode != 0 and "sarif" in r.stderr.lower():
            return None

        try:
            sarif = json.loads(r.stdout)
        except (json.JSONDecodeError, ValueError):
            return None

        findings = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                msg = result.get("message", {}).get("text", "")
                level = result.get("level", "warning")
                rank = result.get("rank", -1)

                fpath, line, col = "", 0, 0
                for loc in result.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    fpath = art.get("uri", "").replace("file://", "")
                    region = phys.get("region", {})
                    line = region.get("startLine", 0)
                    col = region.get("startColumn", 0)
                    break

                cwe_val = self._guess_cwe(rule_id, msg)
                findings.append(self.finding(
                    file=fpath, line=line, column=col,
                    message=msg,
                    severity="warning" if level == "warning" else "info",
                    cwe=cwe_val,
                    category=rule_id,
                    confidence="low",
                    extra={"flawfinder_level": rank},
                ))
        return findings

    def _try_csv(self, target_path: str) -> list[dict]:
        try:
            r = self.run(["flawfinder", "--csv", "--context", target_path], timeout=120)
        except Exception:
            return []

        findings = []
        reader = csv.reader(io.StringIO(r.stdout))
        for row in reader:
            if len(row) < 5:
                continue
            if row[0] == "File":
                continue
            fpath = row[0]
            try:
                line = int(row[1])
            except (ValueError, IndexError):
                line = 0
            col = 0
            try:
                level = int(row[2]) if len(row) > 2 else 0
            except ValueError:
                level = 0
            category = row[3] if len(row) > 3 else ""
            name = row[4] if len(row) > 4 else ""
            msg = row[5] if len(row) > 5 else name

            cwe_val = self._guess_cwe(name, msg)
            findings.append(self.finding(
                file=fpath, line=line, column=col,
                message=msg or name,
                severity="warning" if level >= 3 else "info",
                cwe=cwe_val,
                category=category or name,
                confidence="low",
                extra={"flawfinder_level": level},
            ))
        return findings

    @staticmethod
    def _guess_cwe(name: str, msg: str) -> int | None:
        combined = (name + " " + msg).lower()
        for kw, cwe in CWE_MAP_KEYWORDS.items():
            if kw in combined:
                return cwe
        return None
