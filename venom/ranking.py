from collections import defaultdict

from .cwe import get_cwe, severity_score
from .interface import find_function_at_line

WEIGHTS = {
    "corroboration": 0.30,
    "severity": 0.25,
    "taint": 0.25,
    "centrality": 0.20,
}


def pagerank(graph, damping=0.85, iterations=50, tol=1e-6):
    nodes = set(graph.keys())
    for targets in graph.values():
        nodes.update(targets)
    nodes = list(nodes)
    n = len(nodes)
    if n == 0:
        return {}

    idx = {node: i for i, node in enumerate(nodes)}
    scores = [1.0 / n] * n

    for _ in range(iterations):
        new_scores = [(1.0 - damping) / n] * n
        for node, targets in graph.items():
            if not targets:
                share = scores[idx[node]] * damping / n
                for j in range(n):
                    new_scores[j] += share
            else:
                share = scores[idx[node]] * damping / len(targets)
                for t in targets:
                    if t in idx:
                        new_scores[idx[t]] += share

        diff = sum(abs(new_scores[i] - scores[i]) for i in range(n))
        scores = new_scores
        if diff < tol:
            break

    return {nodes[i]: scores[i] for i in range(n)}


class EvidenceGraph:
    def __init__(self):
        self.call_graph = defaultdict(set)
        self.reverse_graph = defaultdict(set)
        self.file_deps = defaultdict(set)
        self.function_files = {}

    def add_call(self, caller, callee):
        self.call_graph[caller].add(callee)
        self.reverse_graph[callee].add(caller)

    def add_function(self, func_name, file_path):
        self.function_files[func_name] = file_path

    def add_file_dep(self, source_file, included_file):
        self.file_deps[source_file].add(included_file)

    def build_from_interface(self, modeler):
        for func_name, callees in modeler.call_graph.items():
            for callee in callees:
                self.add_call(func_name, callee)

        for func_name, loc in modeler.function_locations.items():
            self.add_function(func_name, loc["file"])

    def compute_pagerank(self):
        graph = {k: list(v) for k, v in self.call_graph.items()}
        return pagerank(graph)

    def get_callers(self, func_name, depth=2):
        result = set()
        frontier = {func_name}
        for _ in range(depth):
            next_frontier = set()
            for f in frontier:
                for caller in self.reverse_graph.get(f, set()):
                    if caller not in result:
                        result.add(caller)
                        next_frontier.add(caller)
            frontier = next_frontier
        return result

    def get_callees(self, func_name, depth=2):
        result = set()
        frontier = {func_name}
        for _ in range(depth):
            next_frontier = set()
            for f in frontier:
                for callee in self.call_graph.get(f, set()):
                    if callee not in result:
                        result.add(callee)
                        next_frontier.add(callee)
            frontier = next_frontier
        return result


class CandidateRanker:
    def __init__(self, evidence_graph, interface_modeler, weights=None):
        self.graph = evidence_graph
        self.modeler = interface_modeler
        self.weights = weights or WEIGHTS
        self._pagerank = None

    def rank(self, findings):
        self._pagerank = self.graph.compute_pagerank()
        max_pr = max(self._pagerank.values()) if self._pagerank else 1.0

        max_corrob = max((f.get("corroboration", 1) for f in findings), default=1)

        scored = []
        for f in findings:
            func_name = find_function_at_line(f["file"], f["line"])
            s_corrob = min(f.get("corroboration", 1) / max(max_corrob, 1), 1.0)
            s_severity = severity_score(f["severity"])
            s_taint = self._taint_score(func_name)
            s_centrality = (self._pagerank.get(func_name, 0) / max_pr) if max_pr > 0 else 0

            score = (
                self.weights["corroboration"] * s_corrob
                + self.weights["severity"] * s_severity
                + self.weights["taint"] * s_taint
                + self.weights["centrality"] * s_centrality
            )

            f["score"] = round(score, 4)
            f["score_breakdown"] = {
                "corroboration": round(s_corrob, 4),
                "severity": round(s_severity, 4),
                "taint": round(s_taint, 4),
                "centrality": round(s_centrality, 4),
            }
            f["function"] = func_name
            scored.append(f)

        scored.sort(key=lambda x: x["score"], reverse=True)
        for i, f in enumerate(scored):
            f["rank"] = i + 1

        return scored

    def _taint_score(self, func_name):
        if not func_name:
            return 0.0
        if self.modeler.function_has_taint_flow(func_name):
            return 1.0
        if self.modeler.function_touches_taint(func_name):
            return 0.6
        taint = self.modeler.get_function_taint(func_name)
        if taint.get("sources") or taint.get("sinks"):
            return 0.4
        return 0.0
