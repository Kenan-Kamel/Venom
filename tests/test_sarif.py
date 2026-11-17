import pytest
from venom.sarif import SarifNormalizer


def _make_finding(**overrides):
    base = {
        "file": "test.c",
        "line": 10,
        "column": 5,
        "message": "buffer overflow",
        "severity": "high",
        "cwe": 120,
        "analyzer": "cppcheck",
        "confidence": "high",
        "code_snippet": "",
        "category": "bugprone",
    }
    base.update(overrides)
    return base


class TestSarifNormalizer:
    def test_ingest_single(self):
        n = SarifNormalizer()
        n.ingest([_make_finding()])
        assert len(n.findings) == 1

    def test_normalize_severity(self):
        n = SarifNormalizer()
        n.ingest([_make_finding(severity="error", cwe=120)])
        assert n.findings[0]["severity"] == "critical"

    def test_normalize_preserves_explicit_severity(self):
        n = SarifNormalizer()
        n.ingest([_make_finding(severity="low")])
        assert n.findings[0]["severity"] == "low"

    def test_dedup_same_location(self):
        n = SarifNormalizer()
        n.ingest([
            _make_finding(analyzer="cppcheck", line=10),
            _make_finding(analyzer="flawfinder", line=11),
        ])
        result = n.deduplicate()
        assert len(result) == 1
        assert set(result[0]["analyzers"]) == {"cppcheck", "flawfinder"}
        assert result[0]["corroboration"] == 2

    def test_dedup_different_location(self):
        n = SarifNormalizer()
        n.ingest([
            _make_finding(line=10),
            _make_finding(line=100),
        ])
        result = n.deduplicate()
        assert len(result) == 2

    def test_dedup_different_cwe(self):
        n = SarifNormalizer()
        n.ingest([
            _make_finding(line=10, cwe=120),
            _make_finding(line=10, cwe=416),
        ])
        result = n.deduplicate()
        assert len(result) == 2

    def test_to_sarif_format(self):
        n = SarifNormalizer()
        n.ingest([_make_finding()])
        n.deduplicate()
        sarif = n.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) >= 1
        assert len(sarif["runs"][0]["results"]) >= 1

    def test_empty(self):
        n = SarifNormalizer()
        n.ingest([])
        result = n.deduplicate()
        assert result == []
