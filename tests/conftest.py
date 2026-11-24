"""Shared fixtures: the socket blocker (D18) and loaders for non-package scripts."""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path
from types import ModuleType

import pytest
from hypothesis import HealthCheck, settings

ROOT = Path(__file__).resolve().parent.parent

# CI-safe Hypothesis profile: no wall-clock deadline (Windows runners are slow and noisy), no
# random seed (a failure reproduces from the same example order), no example database on disk.
settings.register_profile(
    "ci",
    deadline=None,
    derandomize=True,
    database=None,
    max_examples=150,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("ci")


def load_script(name: str, relative: str) -> ModuleType:
    """Import a script that is not part of the package (gate, hook) by file path."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _blocked(*_args: object, **_kwargs: object) -> object:
    raise RuntimeError("network access is blocked in tests")


@pytest.fixture(autouse=True)
def _block_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace socket creation with functions that raise. Only `live` tests may opt out."""
    if request.node.get_closest_marker("live"):
        return
    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)


# The settings ``aisa triage`` reads (config.py). A developer's shell or ``.env`` must never change
# what a test does, so every test starts without them and without a ``.env`` to read (D38).
CONFIG_VARIABLES = ("LLM_PROVIDER", "OLLAMA_BASE_URL", "OLLAMA_MODEL", "OLLAMA_TIMEOUT_SECONDS")


@pytest.fixture(autouse=True)
def _hermetic_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from ai_security_assistant import cli

    for name in CONFIG_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "DOTENV_PATH", tmp_path / "no-dotenv-under-test")


@pytest.fixture(scope="session")
def gate() -> ModuleType:
    return load_script("aisa_gate", "scripts/gate.py")


@pytest.fixture(scope="session")
def hook() -> ModuleType:
    return load_script("aisa_pre_tool_use", ".claude/hooks/pre_tool_use.py")
