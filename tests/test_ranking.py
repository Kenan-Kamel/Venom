import pytest
from venom.ranking import EvidenceGraph, CandidateRanker, pagerank
from venom.interface import InterfaceModeler


def test_pagerank_empty():
    assert pagerank({}) == {}


def test_pagerank_simple():
    graph = {"a": ["b"], "b": ["c"], "c": ["a"]}
    pr = pagerank(graph)
    assert len(pr) == 3
    assert all(v > 0 for v in pr.values())
    assert abs(sum(pr.values()) - 1.0) < 0.01


def test_pagerank_star():
    graph = {"a": ["hub"], "b": ["hub"], "c": ["hub"], "hub": []}
    pr = pagerank(graph)
    assert pr["hub"] > pr["a"]


class TestEvidenceGraph:
    def test_add_call(self):
        g = EvidenceGraph()
        g.add_call("main", "process")
        assert "process" in g.call_graph["main"]
        assert "main" in g.reverse_graph["process"]

    def test_get_callers(self):
        g = EvidenceGraph()
        g.add_call("a", "b")
        g.add_call("b", "c")
        callers = g.get_callers("c", depth=2)
        assert "b" in callers
        assert "a" in callers

    def test_get_callees(self):
        g = EvidenceGraph()
        g.add_call("a", "b")
        g.add_call("b", "c")
        callees = g.get_callees("a", depth=2)
        assert "b" in callees
        assert "c" in callees

    def test_compute_pagerank(self):
        g = EvidenceGraph()
        g.add_call("main", "helper")
        g.add_call("helper", "util")
        pr = g.compute_pagerank()
        assert len(pr) >= 3


class TestCandidateRanker:
    def test_rank_basic(self, tmp_path):
        src = tmp_path / "test.c"
        src.write_text("void foo() { int x; }\n" * 10)
        fpath = str(src)

        modeler = InterfaceModeler()
        modeler.analyze_file(fpath)

        graph = EvidenceGraph()
        graph.build_from_interface(modeler)

        findings = [
            {
                "file": fpath, "line": 1, "message": "bug1",
                "severity": "high", "cwe_id": 416, "cwe_name": "UAF",
                "corroboration": 3, "analyzers": ["a", "b", "c"],
                "confidence": "high", "code_snippet": "",
            },
            {
                "file": fpath, "line": 5, "message": "bug2",
                "severity": "low", "cwe_id": 561, "cwe_name": "Dead Code",
                "corroboration": 1, "analyzers": ["a"],
                "confidence": "low", "code_snippet": "",
            },
        ]

        ranker = CandidateRanker(graph, modeler)
        ranked = ranker.rank(findings)

        assert ranked[0]["rank"] == 1
        assert ranked[0]["score"] >= ranked[1]["score"]
        assert "score_breakdown" in ranked[0]
