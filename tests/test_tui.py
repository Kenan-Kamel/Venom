import pytest
from venom.tui import (
    TOOL_REGISTRY, tool_installed, MENU_ITEMS,
    load_history,
)


def test_tool_registry_count():
    assert len(TOOL_REGISTRY) >= 15


def test_tool_registry_fields():
    for t in TOOL_REGISTRY:
        assert "name" in t
        assert "tier" in t
        assert "desc" in t
        assert t["tier"] in (1, 2, 3, 4)


def test_tool_installed_returns_bool():
    for t in TOOL_REGISTRY:
        result = tool_installed(t)
        assert isinstance(result, bool)


def test_menu_items():
    assert len(MENU_ITEMS) >= 5
    for label, desc in MENU_ITEMS:
        assert isinstance(label, str)
        assert isinstance(desc, str)


def test_load_history_no_file():
    history = load_history()
    assert isinstance(history, list)
