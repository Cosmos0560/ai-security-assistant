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
