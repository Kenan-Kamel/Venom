import json
from collections import defaultdict
from datetime import datetime, timezone


class ReportGenerator:
    def __init__(self, findings, metadata=None, evidence_graph=None, interface_modeler=None):
        self.findings = findings
        self.metadata = metadata or {}
        self.graph = evidence_graph
        self.modeler = interface_modeler

    def summary(self):
        by_severity = defaultdict(int)
        by_cwe = defaultdict(int)
        by_analyzer = defaultdict(int)
        by_file = defaultdict(int)
        by_category = defaultdict(int)
        by_verdict = defaultdict(int)

        for f in self.findings:
            by_severity[f.get("severity", "unknown")] += 1
            cwe_label = f"CWE-{f['cwe_id']}" if f.get("cwe_id") else "Unknown"
            by_cwe[cwe_label] += 1
            by_category[f.get("category", "unknown")] += 1
            by_file[f.get("file", "unknown")] += 1

            for a in f.get("analyzers", []):
                by_analyzer[a] += 1

            triage = f.get("triage", {})
            by_verdict[triage.get("verdict", "untriaged")] += 1

        return {
            "total": len(self.findings),
            "by_severity": dict(by_severity),
            "by_cwe": dict(by_cwe),
            "by_analyzer": dict(by_analyzer),
            "by_file": dict(by_file),
            "by_category": dict(by_category),
            "by_verdict": dict(by_verdict),
        }

    def file_heatmap(self):
        heatmap = defaultdict(list)
        for f in self.findings:
            heatmap[f.get("file", "")].append({
                "line": f.get("line", 0),
                "severity": f.get("severity", "medium"),
                "cwe_id": f.get("cwe_id", 0),
                "message": f.get("message", ""),
            })
        return dict(heatmap)

    def graph_data(self):
        if not self.graph:
            return {"nodes": [], "edges": []}

        pagerank = self.graph.compute_pagerank()
        max_pr = max(pagerank.values()) if pagerank else 1.0

        findings_by_func = defaultdict(list)
        for f in self.findings:
            func = f.get("function")
            if func:
                findings_by_func[func].append(f)

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        nodes = []
        seen_funcs = set()

        for func_name, file_path in self.graph.function_files.items():
            seen_funcs.add(func_name)
            func_findings = findings_by_func.get(func_name, [])
            worst_sev = "none"
            if func_findings:
                worst_sev = min(
                    (f.get("severity", "unknown") for f in func_findings),
                    key=lambda s: sev_order.get(s, 4),
                )

            taint = {"sources": [], "sinks": []}
            if self.modeler:
                taint = self.modeler.get_function_taint(func_name)

            loc = self.modeler.function_locations.get(func_name, {}) if self.modeler else {}

            nodes.append({
                "id": func_name,
                "file": file_path,
                "line": loc.get("line", 0),
                "findings_count": len(func_findings),
                "worst_severity": worst_sev,
                "centrality": round(pagerank.get(func_name, 0) / max_pr, 4) if max_pr > 0 else 0,
                "has_taint": bool(taint.get("sources") or taint.get("sinks")),
                "taint_sources": taint.get("sources", []),
                "taint_sinks": taint.get("sinks", []),
                "finding_ids": [f.get("id", "") for f in func_findings],
                "cwe_ids": list({str(f.get("cwe_id", "")) for f in func_findings if f.get("cwe_id")}),
                "analyzers": list({a for f in func_findings for a in f.get("analyzers", [])}),
            })

        edges = []
        for caller, callees in self.graph.call_graph.items():
            for callee in callees:
                if caller != callee and caller in self.graph.function_files and callee in self.graph.function_files:
                    edges.append({"source": caller, "target": callee})

        return {"nodes": nodes, "edges": edges}

    def codemap_data(self, base_path=None):
        import os
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

        findings_by_file = defaultdict(list)
        for f in self.findings:
            fp = f.get("file", "")
            findings_by_file[fp].append(f)

        file_entries = {}
        for fp, ffindings in findings_by_file.items():
            loc = 0
            try:
                with open(fp, "r", errors="replace") as fh:
                    loc = sum(1 for _ in fh)
            except OSError:
                pass

            worst = min(
                (f.get("severity", "unknown") for f in ffindings),
                key=lambda s: sev_order.get(s, 4),
            )

            rel = fp
            if base_path and fp.startswith(base_path):
                rel = fp[len(base_path):].lstrip("/")

            markers = []
            for f in ffindings:
                markers.append({
                    "line": f.get("line", 0),
                    "severity": f.get("severity", "medium"),
                    "cwe_id": str(f.get("cwe_id", "")) if f.get("cwe_id") else "",
                    "message": f.get("message", "")[:120],
                    "function": f.get("function", ""),
                    "analyzers": f.get("analyzers", []),
                    "id": f.get("id", ""),
                })

            file_entries[rel] = {
                "loc": loc,
                "findings": len(ffindings),
                "worst_severity": worst,
                "markers": sorted(markers, key=lambda m: m["line"]),
            }

        # Build directory tree
        tree = {"name": "/", "children": {}, "findings": 0, "loc": 0, "worst_severity": "none"}
        for rel_path, info in file_entries.items():
            parts = rel_path.split("/")
            node = tree
            for part in parts[:-1]:
                if part not in node["children"]:
                    node["children"][part] = {"name": part, "children": {}, "findings": 0, "loc": 0, "worst_severity": "none"}
                node = node["children"][part]
                node["findings"] += info["findings"]
                node["loc"] += info["loc"]
                if sev_order.get(info["worst_severity"], 4) < sev_order.get(node["worst_severity"], 4):
                    node["worst_severity"] = info["worst_severity"]

            fname = parts[-1]
            node["children"][fname] = {
                "name": fname,
                "path": rel_path,
                "loc": info["loc"],
                "findings": info["findings"],
                "worst_severity": info["worst_severity"],
                "markers": info["markers"],
            }
            tree["findings"] += info["findings"]
            tree["loc"] += info["loc"]
            if sev_order.get(info["worst_severity"], 4) < sev_order.get(tree["worst_severity"], 4):
                tree["worst_severity"] = info["worst_severity"]

        def flatten_tree(node):
            if "markers" in node:
                return node
            result = {
                "name": node["name"],
                "findings": node["findings"],
                "loc": node["loc"],
                "worst_severity": node["worst_severity"],
                "children": [],
            }
            for child in sorted(node["children"].values(),
                                key=lambda c: (-c["findings"], c["name"])):
                result["children"].append(flatten_tree(child))
            return result

        return flatten_tree(tree)

    def generate_json(self, output_path):
        data = {
            "findings": self._serialize_findings(),
            "summary": self.summary(),
            "metadata": self._build_metadata(),
        }
        with open(output_path, "w") as fp:
            json.dump(data, fp, indent=2)
        return output_path

    def generate_html_data(self, output_path, base_path=None):
        data = {
            "findings": self._serialize_findings(),
            "summary": self.summary(),
            "metadata": self._build_metadata(),
            "files": self.file_heatmap(),
            "graph": self.graph_data(),
            "codemap": self.codemap_data(base_path=base_path),
        }
        with open(output_path, "w") as fp:
            json.dump(data, fp, indent=2)
        return output_path

    def _build_metadata(self):
        meta = {
            "target": self.metadata.get("target", "unknown"),
            "analyzers_used": self.metadata.get("analyzers_used", []),
            "tiers_run": self.metadata.get("tiers_run", []),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": self.metadata.get("version", "0.1.0"),
            "total_files_scanned": self.metadata.get("total_files_scanned", 0),
            "command": self.metadata.get("command", ""),
        }
        git = self.metadata.get("git")
        if git:
            meta["git"] = git
        return meta

    def generate_sarif(self, output_path):
        data = self._build_sarif()
        with open(output_path, "w") as fp:
            json.dump(data, fp, indent=2)
        return output_path

    def _build_sarif(self):
        results = []
        for f in self.findings:
            result = {
                "ruleId": f.get("category", "unknown"),
                "level": "error" if f.get("severity") in ("critical", "high") else "warning",
                "message": {"text": f.get("message", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", "")},
                        "region": {
                            "startLine": f.get("line", 0),
                            "startColumn": f.get("column", 0),
                        },
                    }
                }],
            }
            if f.get("cwe_id"):
                result["taxa"] = [{"id": str(f["cwe_id"]), "toolComponent": {"name": "CWE"}}]
            results.append(result)

        return {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Venom",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/venom-analyzer/venom",
                    }
                },
                "results": results,
            }],
        }

    def _serialize_findings(self):
        out = []
        for f in self.findings:
            triage = f.get("triage") or {}
            entry = {
                "id": f.get("id", ""),
                "rank": f.get("rank", 0),
                "composite_score": f.get("score", 0),
                "score_breakdown": {
                    "corroboration": f.get("score_breakdown", {}).get("corroboration", 0),
                    "cwe_severity": f.get("score_breakdown", {}).get("severity", 0),
                    "taint": f.get("score_breakdown", {}).get("taint", 0),
                    "centrality": f.get("score_breakdown", {}).get("centrality", 0),
                },
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "column": f.get("column", 0),
                "function": f.get("function", ""),
                "message": f.get("message", ""),
                "severity": f.get("severity", "medium"),
                "cwe_id": str(f.get("cwe_id", "")) if f.get("cwe_id") else "",
                "cwe_name": f.get("cwe_name", ""),
                "cwe_description": f.get("cwe_name", ""),
                "category": f.get("category", ""),
                "analyzers": f.get("analyzers", []),
                "confidence": f.get("confidence", "medium"),
                "code_snippet": f.get("code_snippet", ""),
            }
            if triage and triage.get("verdict") not in (None, "untriaged"):
                entry["llm_verdict"] = triage.get("verdict")
                entry["llm_reachable"] = triage.get("reachable")
                entry["llm_impact"] = triage.get("impact")
                entry["llm_explanation"] = triage.get("explanation")
            out.append(entry)
        return out
