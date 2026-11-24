"""Phase 8 gate additions: ``.env`` never staged, ``providers/ollama.py`` imports only stdlib and
project modules, and the default model name lives only in its constant (D37).

The model name is never written here: tests read it from ``DEFAULT_MODEL``.
"""

from __future__ import annotations

from types import ModuleType

import pytest

from ai_security_assistant.providers.ollama import DEFAULT_MODEL

OLLAMA = "src/ai_security_assistant/providers/ollama.py"

# ---------------------------------------------------------------- .env is never staged


@pytest.mark.parametrize(
    "path",
    [".env", "sub/.env", "a/b/.env", ".env.local", ".env.production", "docs/.env.backup"],
)
def test_a_staged_dotenv_fails_the_gate(gate: ModuleType, path: str) -> None:
    problems = gate.hygiene_problems(["README.md", path])
    assert len(problems) == 1
    assert "must not be tracked or staged" in problems[0]
    assert path in problems[0]


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        "sub/.env.example",
        "env.py",
        "src/environment.py",
        "docs/dotenv.md",
        ".envrc",
    ],
)
def test_near_misses_pass(gate: ModuleType, path: str) -> None:
    assert gate.hygiene_problems([path]) == []


def test_the_real_tree_has_no_dotenv_tracked(gate: ModuleType) -> None:
    assert gate.hygiene_problems(gate.tracked_paths()) == []


# ---------------------------------------------------------------- imports (AST)

ALLOWED = ("ai_security_assistant",)


def test_stdlib_and_project_imports_pass(gate: ModuleType) -> None:
    source = (
        "from __future__ import annotations\n"
        "import json, os.path\n"
        "import urllib.request as ur\n"
        "from collections.abc import Callable\n"
        "from urllib.parse import urlsplit\n"
        "from ai_security_assistant.schema import tool_input_schema\n"
        "from . import base\n"
        "from .base import CallBudget\n"
        "from .. import models\n"
    )
    assert gate.import_problems(source, "x.py", ALLOWED) == []


@pytest.mark.parametrize(
    ("source", "needle"),
    [
        ("import requests\n", "import of requests"),
        ("import httpx.sync\n", "import of httpx.sync"),
        ("import json, requests\n", "import of requests"),
        ("from ollama import Client\n", "import from ollama"),
        ("from pydantic import BaseModel\n", "import from pydantic"),
        ("import anthropic as a\n", "import of anthropic"),
        (
            "import importlib\nimportlib.import_module('requests')\n",
            "dynamic import via import_module",
        ),
        ("__import__('requests')\n", "dynamic import via __import__"),
        ("from importlib import import_module\nimport_module(name)\n", "dynamic import"),
    ],
)
def test_other_imports_fail(gate: ModuleType, source: str, needle: str) -> None:
    problems = gate.import_problems(source, "x.py", ALLOWED)
    assert problems, source
    assert any(needle in p for p in problems), problems
    assert all(p.startswith("x.py:") for p in problems)


def test_the_real_provider_module_passes_and_the_check_is_registered(gate: ModuleType) -> None:
    assert gate.check_ollama_imports() == []
    assert gate.check_ollama_imports in [check for _name, check in gate.CHECKS]


def test_a_provider_module_with_a_third_party_import_would_fail(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
) -> None:
    bad = tmp_path / "ollama.py"  # type: ignore[operator]
    bad.write_text("import httpx\n", encoding="utf-8")
    monkeypatch.setattr(gate, "OLLAMA_MODULE", bad)
    assert gate.check_ollama_imports() == [f"{OLLAMA}:1: import of httpx"]


# ---------------------------------------------------------------- the model literal


def test_the_constant_is_read_from_the_module(gate: ModuleType) -> None:
    source = f'DEFAULT_MODEL: Final = "{DEFAULT_MODEL}"\nOTHER: Final = "x"\n'
    assert gate.default_model_value(source) == DEFAULT_MODEL
    assert gate.default_model_value('X = 1\nNAME: Final = "n"\n', "NAME") == "n"


@pytest.mark.parametrize(
    "source", ["", "DEFAULT_MODEL = 5\n", "DEFAULT_MODEL: Final = some_call()\n", "OTHER = 'x'\n"]
)
def test_a_missing_or_odd_constant_is_an_error(gate: ModuleType, source: str) -> None:
    with pytest.raises(ValueError, match="no string constant DEFAULT_MODEL"):
        gate.default_model_value(source)


def test_the_literal_is_allowed_once_in_the_provider_only(gate: ModuleType) -> None:
    files = [
        (OLLAMA, f'DEFAULT_MODEL: Final = "{DEFAULT_MODEL}"\n'),
        ("src/ai_security_assistant/cli.py", "no model here\n"),
        ("tests/test_x.py", "from m import DEFAULT_MODEL\n"),
        ("tests/fixtures/ollama/chat_x.json", f'{{"model": "{DEFAULT_MODEL}"}}\n'),
    ]
    assert gate.model_literal_problems(DEFAULT_MODEL, files) == []


@pytest.mark.parametrize(
    "rel", ["src/ai_security_assistant/cli.py", "tests/test_x.py", "tests/x.md"]
)
def test_the_literal_anywhere_else_fails(gate: ModuleType, rel: str) -> None:
    files = [
        (OLLAMA, f'DEFAULT_MODEL: Final = "{DEFAULT_MODEL}"\n'),
        (rel, f'model = "{DEFAULT_MODEL}"\n'),
    ]
    assert gate.model_literal_problems(DEFAULT_MODEL, files) == [
        f"{rel}: the default model literal belongs in {OLLAMA} only"
    ]


@pytest.mark.parametrize("text", ["", f"a = '{DEFAULT_MODEL}'\nb = '{DEFAULT_MODEL}'\n"])
def test_the_provider_must_hold_it_exactly_once(gate: ModuleType, text: str) -> None:
    count = text.count(DEFAULT_MODEL)
    assert gate.model_literal_problems(DEFAULT_MODEL, [(OLLAMA, text)]) == [
        f"{OLLAMA}: the default model must appear exactly once, found {count}"
    ]


def test_the_fixture_folder_is_exempt_but_a_lookalike_folder_is_not(gate: ModuleType) -> None:
    exempt = [("tests/fixtures/ollama/a.json", DEFAULT_MODEL)]
    assert gate.model_literal_problems(DEFAULT_MODEL, exempt) == []
    other = [("tests/fixtures/ollama_notes/a.json", DEFAULT_MODEL)]
    assert len(gate.model_literal_problems(DEFAULT_MODEL, other)) == 1


def test_the_real_tree_passes_and_the_check_is_registered(gate: ModuleType) -> None:
    assert gate.check_model_literal() == []
    assert gate.check_model_literal in [check for _name, check in gate.CHECKS]


def test_the_text_walk_skips_caches_and_binary_files(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
) -> None:
    root = tmp_path  # type: ignore[assignment]
    (root / "src" / "__pycache__").mkdir(parents=True)  # type: ignore[operator]
    (root / "src" / "__pycache__" / "x.pyc").write_bytes(DEFAULT_MODEL.encode())  # type: ignore[operator]
    (root / "src" / "blob.bin").write_bytes(b"\x00" + DEFAULT_MODEL.encode())  # type: ignore[operator]
    (root / "src" / "a.py").write_bytes(b"a = 1\r\nb = 2\r\n")  # type: ignore[operator]
    monkeypatch.setattr(gate, "ROOT", root)
    assert list(gate._text_files(["src"])) == [("src/a.py", "a = 1\nb = 2\n")]
