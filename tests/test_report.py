import json
import os
import pytest
from venom.report import ReportGenerator


def _make_findings():
    return [
        {
            "id": "abc123",
            "file": "/tmp/test.c",
            "line": 10,
            "column": 5,
            "message": "buffer overflow in strcpy",
            "severity": "critical",
            "cwe_id": 120,
            "cwe_name": "Buffer Copy without Checking Size",
            "category": "memory-safety",
            "analyzers": ["cppcheck", "flawfinder"],
            "confidence": "high",
            "code_snippet": "strcpy(buf, input);",
            "score": 0.85,
            "rank": 1,
            "score_breakdown": {
                "corroboration": 0.5,
                "severity": 1.0,
                "taint": 0.8,
                "centrality": 0.3,
            },
            "function": "process_input",
        },
        {
            "id": "def456",
            "file": "/tmp/test.c",
            "line": 50,
            "column": 1,
            "message": "memory leak",
            "severity": "medium",
            "cwe_id": 401,
            "cwe_name": "Missing Release of Memory",
            "category": "memory-safety",
            "analyzers": ["infer"],
            "confidence": "medium",
            "code_snippet": "malloc(1024);",
            "score": 0.45,
            "rank": 2,
            "score_breakdown": {
                "corroboration": 0.1,
                "severity": 0.5,
                "taint": 0.0,
                "centrality": 0.1,
            },
        },
    ]


class TestReportGenerator:
    def test_summary(self):
        gen = ReportGenerator(_make_findings())
        s = gen.summary()
        assert s["total"] == 2
        assert s["by_severity"]["critical"] == 1
        assert s["by_severity"]["medium"] == 1

    def test_generate_json(self, tmp_path):
        out = str(tmp_path / "results.json")
        gen = ReportGenerator(_make_findings(), {"target": "/tmp/test.c"})
        gen.generate_json(out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert len(data["findings"]) == 2
        assert "summary" in data

    def test_generate_sarif(self, tmp_path):
        out = str(tmp_path / "results.sarif")
        gen = ReportGenerator(_make_findings(), {"target": "/tmp/test.c"})
        gen.generate_sarif(out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

    def test_generate_html_data(self, tmp_path):
        out = str(tmp_path / "data.json")
        gen = ReportGenerator(_make_findings(), {"target": "/tmp/test.c"})
        gen.generate_html_data(out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert "findings" in data
        assert "codemap" in data
        assert "graph" in data

    def test_file_heatmap(self):
        gen = ReportGenerator(_make_findings())
        hm = gen.file_heatmap()
        assert "/tmp/test.c" in hm
        assert len(hm["/tmp/test.c"]) == 2

    def test_empty_findings(self, tmp_path):
        gen = ReportGenerator([])
        s = gen.summary()
        assert s["total"] == 0
        out = str(tmp_path / "empty.json")
        gen.generate_json(out)
        with open(out) as f:
            data = json.load(f)
        assert data["findings"] == []
