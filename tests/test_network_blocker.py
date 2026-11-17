from __future__ import annotations

import os
import socket

import pytest


def test_socket_constructor_raises() -> None:
    with pytest.raises(RuntimeError, match="network access is blocked"):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_create_connection_raises() -> None:
    with pytest.raises(RuntimeError, match="network access is blocked"):
        socket.create_connection(("192.0.2.1", 9))


def test_live_marker_is_registered_and_deselected_by_default(pytestconfig: pytest.Config) -> None:
    markers = pytestconfig.getini("markers")
    assert any(str(m).startswith("live:") for m in markers)
    assert "not live" in str(pytestconfig.getini("addopts"))


def test_api_key_is_unset_in_ci() -> None:
    if os.environ.get("CI"):
        assert "ANTHROPIC_API_KEY" not in os.environ


def test_live_switch_is_unset_in_ci() -> None:
    if os.environ.get("CI"):
        assert "AISA_LIVE" not in os.environ


def test_the_ci_workflow_sets_neither_live_variable() -> None:
    from pathlib import Path

    workflow = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
    text = workflow.read_text(encoding="utf-8")
    assert "AISA_LIVE" not in text
    assert "ANTHROPIC_API_KEY" not in text
    assert "anthropic" not in text.lower().replace("ai-security-assistant", "")


def test_the_live_test_is_skipped_unless_both_switches_are_present() -> None:
    from tests.live import test_anthropic_live as live

    skips = [m for m in live.pytestmark if m.name == "skipif"]
    assert len(skips) == 1
    assert "AISA_LIVE" in live.__doc__ and "ANTHROPIC_API_KEY" in live.__doc__
    assert any(m.name == "live" for m in live.pytestmark)
