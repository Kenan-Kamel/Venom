import pytest
from venom.analyzers import (
    get_all_analyzers, get_analyzers_by_tier, get_analyzer_tier,
    ALL_ANALYZERS, ANALYZER_TIERS,
)
from venom.analyzers.base import Analyzer


def test_all_analyzers_count():
    assert len(ALL_ANALYZERS) == 16


def test_all_analyzers_are_subclasses():
    for cls in ALL_ANALYZERS:
        assert issubclass(cls, Analyzer)


def test_all_analyzers_instantiate():
    instances = get_all_analyzers()
    assert len(instances) == 16
    names = [a.name for a in instances]
    assert len(set(names)) == 16


def test_tier_structure():
    assert set(ANALYZER_TIERS.keys()) == {1, 2, 3, 4}
    for tier_num, info in ANALYZER_TIERS.items():
        assert "name" in info
        assert "description" in info
        assert "analyzers" in info
        assert len(info["analyzers"]) >= 2


def test_all_tier_analyzers_exist():
    instances = {a.name: a for a in get_all_analyzers()}
    for tier_num, info in ANALYZER_TIERS.items():
        for name in info["analyzers"]:
            assert name in instances, f"Tier {tier_num} references '{name}' but no analyzer has that name"


def test_get_analyzer_tier():
    assert get_analyzer_tier("cppcheck") == 1
    assert get_analyzer_tier("infer") == 3
    assert get_analyzer_tier("codeql") == 4
    assert get_analyzer_tier("nonexistent") == 0


def test_get_analyzers_by_tier():
    tiers = get_analyzers_by_tier()
    assert len(tiers) == 4
    for tier_num in range(1, 5):
        assert tier_num in tiers
        assert "analyzers" in tiers[tier_num]
        assert all(isinstance(a, Analyzer) for a in tiers[tier_num]["analyzers"])


def test_analyzer_names_unique():
    names = [a.name for a in get_all_analyzers()]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("cls", ALL_ANALYZERS)
def test_analyzer_has_required_methods(cls):
    instance = cls()
    assert hasattr(instance, "name")
    assert hasattr(instance, "is_available")
    assert hasattr(instance, "analyze")
    assert isinstance(instance.name, str)
    assert len(instance.name) > 0
