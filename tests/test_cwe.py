import pytest
from venom.cwe import get_cwe, get_severity, severity_score, CWE_DATABASE


def test_known_cwe():
    cwe = get_cwe(416)
    assert cwe["id"] == 416
    assert cwe["name"] == "Use After Free"
    assert cwe["severity"] == "critical"
    assert cwe["category"] == "memory-safety"


def test_unknown_cwe():
    cwe = get_cwe(99999)
    assert cwe["id"] == 99999
    assert cwe["name"] == "Unknown"
    assert cwe["severity"] == "medium"


def test_zero_cwe():
    cwe = get_cwe(0)
    assert cwe["name"] == "Unknown"


def test_none_cwe():
    cwe = get_cwe(None)
    assert cwe["id"] == 0


def test_severity_score():
    assert severity_score("critical") == 1.0
    assert severity_score("high") == 0.8
    assert severity_score("medium") == 0.5
    assert severity_score("low") == 0.2
    assert severity_score("garbage") == 0.3


def test_get_severity():
    assert get_severity(120) == "critical"
    assert get_severity(476) == "high"
    assert get_severity(401) == "medium"
    assert get_severity(252) == "low"


def test_all_cwes_have_required_fields():
    for cwe_id, cwe in CWE_DATABASE.items():
        assert "id" in cwe
        assert "name" in cwe
        assert "severity" in cwe
        assert "category" in cwe
        assert cwe["id"] == cwe_id
        assert cwe["severity"] in ("critical", "high", "medium", "low")
