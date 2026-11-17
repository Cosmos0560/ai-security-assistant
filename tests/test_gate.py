"""Tests for scripts/gate.py helpers. Key-like and email-shaped strings are built at runtime."""

from __future__ import annotations

import hashlib
from types import ModuleType

import pytest

EMAIL = "".join(["jane", ".", "doe", "@", "example", ".", "com"])
AWS_KEY = "AK" + "IA" + "A" * 16
GH_TOKEN = "gh" + "p_" + "a" * 36
SK_KEY = "sk" + "-" + "a" * 30
PEM = "-----" + "BEGIN RSA PRIVATE" + " KEY" + "-----"


# ---------------------------------------------------------------- LF helper


def test_lf_helper_same_hash_for_crlf_and_lf(gate: ModuleType) -> None:
    lf = b"line one\nline two\n"
    crlf = b"line one\r\nline two\r\n"
    assert gate.sha256_lf(lf) == gate.sha256_lf(crlf)
    assert gate.sha256_lf(lf) == hashlib.sha256(lf).hexdigest()
    assert gate.normalize_lf(crlf) == lf


def test_lf_helper_keeps_lone_cr(gate: ModuleType) -> None:
    assert gate.normalize_lf(b"a\rb") == b"a\rb"


# ---------------------------------------------------------------- AST ban


def test_ast_ban_flags_bad_sample(gate: ModuleType) -> None:
    bad = "\n".join(
        [
            "import subprocess",
            "import subprocess as sp",
            "from subprocess import run",
            "import os",
            "import os as o",
            "from os import system",
            "os.system('x')",
            "os.popen('x')",
            "os.execv('x', [])",
            "os.spawnl(0, 'x')",
            "o.system('x')",
            "eval('1')",
            "exec('1')",
            "compile('1', 'f', 'eval')",
            "__import__('x')",
        ]
    )
    problems = gate.check_source(bad, "bad.py")
    # 3 subprocess imports, 1 from-os import, 5 os attribute uses (one via alias), 4 builtins
    assert len(problems) == 13
    text = "\n".join(problems)
    for needle in ("subprocess", "os.system", "os.popen", "os.execv", "os.spawnl", "eval", "exec"):
        assert needle in text


def test_ast_ban_allows_re_compile_and_safe_code(gate: ModuleType) -> None:
    ok = "\n".join(
        [
            "import os",
            "import re",
            "pattern = re.compile('x')",
            "path = os.path.join('a', 'b')",
            "home = os.environ.get('HOME')",
            "class Thing:",
            "    def compile(self) -> int:",
            "        return 1",
            "Thing().compile()",
        ]
    )
    assert gate.check_source(ok, "ok.py") == []


def test_ast_ban_on_the_real_src_tree(gate: ModuleType) -> None:
    assert gate.check_ast_ban() == []


# ---------------------------------------------------------------- scan patterns


@pytest.mark.parametrize(
    ("text", "name"),
    [
        (f"contact {EMAIL} today", "email address"),
        (f"key = {AWS_KEY}", "aws access key id"),
        (f"token {GH_TOKEN}", "github token"),
        (f"export K={SK_KEY}", "api key (sk- prefix)"),
        (PEM, "private key header"),
    ],
)
def test_scan_catches_runtime_built_strings(gate: ModuleType, text: str, name: str) -> None:
    hits = gate.scan_text("first line\n" + text)
    assert (2, name) in hits


@pytest.mark.parametrize(
    "text",
    [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1",
        "stash@{0} and @pytest.fixture and user@host",
        "a risk-assessment-framework-that-is-long-enough-to-matter",
        "AKIA is a prefix but not a key",
        "plain text",
    ],
)
def test_scan_ignores_near_misses(gate: ModuleType, text: str) -> None:
    assert gate.scan_text(text) == []


def test_scan_never_reports_the_matched_text(gate: ModuleType) -> None:
    hits = gate.scan_text(f"x {AWS_KEY}")
    assert all(AWS_KEY not in repr(hit) for hit in hits)


def test_gate_source_does_not_match_its_own_patterns(gate: ModuleType) -> None:
    source = gate.ROOT.joinpath("scripts", "gate.py").read_text(encoding="utf-8")
    assert gate.scan_text(source) == []


def test_tracked_files_are_clean(gate: ModuleType) -> None:
    assert gate.check_secret_scan() == []


# ---------------------------------------------------------------- graph and hygiene


def test_graph_problems(gate: ModuleType) -> None:
    assert gate.graph_problems(["src/a.py", "graphify-out/graph.json"]) == [
        "graph output is tracked or staged: graphify-out/graph.json"
    ]
    assert gate.graph_problems(["src/a.py", "docs/graphify-out.md"]) == []


def test_graph_dir_is_ignored(gate: ModuleType) -> None:
    assert gate.check_graph() == []


def test_hygiene_problems(gate: ModuleType) -> None:
    assert len(gate.hygiene_problems(["AGENTS.md"])) == 1
    assert len(gate.hygiene_problems(["sub/agents.md"])) == 1
    assert len(gate.hygiene_problems([".codex/config.toml"])) == 1
    assert len(gate.hygiene_problems(["a/.codex/x"])) == 1
    assert gate.hygiene_problems(["README.md", "src/codex.py", "docs/agents-notes.md"]) == []


# ---------------------------------------------------------------- detector independence (D16)


@pytest.mark.parametrize(
    "source",
    [
        "import ai_security_assistant.detector.heuristics",
        "import ai_security_assistant.detector.heuristics as h",
        "from ai_security_assistant.detector.heuristics import RULES",
        "from ai_security_assistant.detector import canary",
        "from ai_security_assistant import detector",
        "from ai_security_assistant import detector as d",
        "from .. import detector",
        "from ..detector import canary",
        "from ..detector.heuristics import RULES",
        "import importlib\nimportlib.import_module('ai_security_assistant.detector.canary')",
        "__import__('ai_security_assistant.detector')",
        "def f():\n    from ai_security_assistant.detector.canary import new_canary",
    ],
)
def test_detector_import_is_flagged(gate: ModuleType, source: str) -> None:
    assert len(gate.check_no_detector_import(source, "x.py")) == 1


@pytest.mark.parametrize(
    "source",
    [
        "from ai_security_assistant.wrap import unwrap",
        "from ai_security_assistant import wrap",
        "from ai_security_assistant.schema import Severity",
        "import re\nre.compile('detector')",
        "x = 'detector'",
        "import importlib\nimportlib.import_module('ai_security_assistant.wrap')",
        "from .naive_rules import extract_directives",
        "print('detector')",
    ],
)
def test_other_imports_are_allowed(gate: ModuleType, source: str) -> None:
    assert gate.check_no_detector_import(source, "x.py") == []


def test_the_two_mock_modules_are_checked_and_clean(gate: ModuleType) -> None:
    assert gate.INDEPENDENT_OF_DETECTOR == (
        "src/ai_security_assistant/providers/mock.py",
        "src/ai_security_assistant/providers/naive_rules.py",
    )
    for rel in gate.INDEPENDENT_OF_DETECTOR:
        assert gate.ROOT.joinpath(rel).is_file()
    assert gate.check_detector_independence() == []


def test_the_independence_check_is_part_of_the_gate(gate: ModuleType) -> None:
    assert gate.check_detector_independence in [check for _name, check in gate.CHECKS]


def test_gate_accepts_no_flags(gate: ModuleType) -> None:
    with pytest.raises(SystemExit) as exc:
        gate.main(["--live"])
    assert exc.value.code == 2
