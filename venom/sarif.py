import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from .cwe import get_cwe, severity_score


class SarifNormalizer:
    def __init__(self, line_proximity=3):
        self.line_proximity = line_proximity
        self.findings = []

    def ingest(self, raw_findings):
        for f in raw_findings:
            self.findings.append(self._normalize_one(f))

    def _normalize_one(self, raw):
        cwe_id = raw.get("cwe_id") or raw.get("cwe") or 0
        cwe = get_cwe(cwe_id)
        raw_sev = raw.get("severity", "")
        if raw_sev in ("critical", "high", "medium", "low"):
            severity = raw_sev
        elif cwe["severity"] != "medium" or cwe_id:
            severity = cwe["severity"]
        elif raw_sev == "error":
            severity = "high"
        else:
            severity = "medium"

        return {
            "id": str(uuid.uuid4()),
            "file": raw.get("file", ""),
            "line": raw.get("line", 0),
            "column": raw.get("column", 0),
            "end_line": raw.get("end_line", raw.get("line", 0)),
            "message": raw.get("message", ""),
            "severity": severity,
            "cwe_id": cwe_id,
            "cwe_name": cwe["name"],
            "category": cwe["category"],
            "analyzer": raw.get("analyzer", "unknown"),
            "confidence": raw.get("confidence", "medium"),
            "code_snippet": raw.get("code_snippet", ""),
            "rule_id": raw.get("category", raw.get("rule_id", "")),
            "raw": raw,
        }

    def deduplicate(self):
        groups = defaultdict(list)
        for f in self.findings:
            key = (f["file"], f["cwe_id"])
            groups[key].append(f)

        unified = []
        for (_file, _cwe), cluster in groups.items():
            cluster.sort(key=lambda x: x["line"])
            merged = []
            for f in cluster:
                placed = False
                for group in merged:
                    if abs(f["line"] - group[0]["line"]) <= self.line_proximity:
                        group.append(f)
                        placed = True
                        break
                if not placed:
                    merged.append([f])

            for group in merged:
                unified.append(self._merge_group(group))

        self.findings = unified
        return unified

    def _merge_group(self, group):
        analyzers = list({f["analyzer"] for f in group})
        best = max(group, key=lambda f: severity_score(f["severity"]))
        corroboration = len(analyzers)
        confidence_map = {"high": 3, "medium": 2, "low": 1}
        max_conf = max(confidence_map.get(f["confidence"], 1) for f in group)
        if corroboration >= 3:
            boosted_conf = "high"
        elif corroboration >= 2 or max_conf >= 3:
            boosted_conf = "high" if max_conf >= 2 else "medium"
        else:
            boosted_conf = {3: "high", 2: "medium"}.get(max_conf, "low")

        messages = list(dict.fromkeys(f["message"] for f in group))

        return {
            "id": str(uuid.uuid4()),
            "file": best["file"],
            "line": best["line"],
            "column": best["column"],
            "end_line": max(f["end_line"] for f in group),
            "message": messages[0],
            "all_messages": messages,
            "severity": best["severity"],
            "cwe_id": best["cwe_id"],
            "cwe_name": best["cwe_name"],
            "category": best["category"],
            "analyzers": analyzers,
            "corroboration": corroboration,
            "confidence": boosted_conf,
            "code_snippet": best["code_snippet"],
            "rule_ids": list({f["rule_id"] for f in group if f["rule_id"]}),
            "raw_findings": [f["raw"] for f in group],
        }

    def get_findings(self):
        return self.findings

    def to_sarif(self):
        runs = []
        by_analyzer = defaultdict(list)
        for f in self.findings:
            for a in (f.get("analyzers") or [f.get("analyzer", "unknown")]):
                by_analyzer[a].append(f)

        for analyzer, findings in by_analyzer.items():
            results = []
            for f in findings:
                result = {
                    "ruleId": f.get("rule_ids", [""])[0] if f.get("rule_ids") else f.get("cwe_name", ""),
                    "level": _sarif_level(f["severity"]),
                    "message": {"text": f["message"]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {
                                "startLine": f["line"],
                                "startColumn": f.get("column", 1),
                            },
                        }
                    }],
                }
                if f["cwe_id"]:
                    result["taxa"] = [{"toolComponent": {"name": "CWE"}, "id": str(f["cwe_id"])}]
                results.append(result)

            runs.append({
                "tool": {"driver": {"name": analyzer, "version": "1.0"}},
                "results": results,
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }

    def to_json(self):
        return [_finding_to_json(f) for f in self.findings]

    def export_sarif(self, path):
        with open(path, "w") as fp:
            json.dump(self.to_sarif(), fp, indent=2)

    def export_json(self, path):
        with open(path, "w") as fp:
            json.dump(self.to_json(), fp, indent=2)


def _sarif_level(severity):
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity, "warning")


def _finding_to_json(f):
    return {
        "id": f["id"],
        "file": f["file"],
        "line": f["line"],
        "column": f.get("column", 0),
        "end_line": f.get("end_line", f["line"]),
        "message": f["message"],
        "all_messages": f.get("all_messages", [f["message"]]),
        "severity": f["severity"],
        "cwe_id": f["cwe_id"],
        "cwe_name": f["cwe_name"],
        "category": f["category"],
        "analyzers": f.get("analyzers", []),
        "corroboration": f.get("corroboration", 1),
        "confidence": f.get("confidence", "medium"),
        "code_snippet": f.get("code_snippet", ""),
        "rule_ids": f.get("rule_ids", []),
        "score": f.get("score", 0),
        "rank": f.get("rank", 0),
        "triage": f.get("triage"),
        "taint_context": f.get("taint_context"),
    }
