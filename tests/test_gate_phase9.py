"""Phase 9 gate addition: the Windows KB invariants (D39), checked with the standard library."""

from __future__ import annotations

import json
from types import ModuleType
from typing import Any

import pytest


def document(gate: ModuleType) -> dict[str, Any]:
    loaded = json.loads(gate.KB_FILE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def problems_after(gate: ModuleType, mutate: Any) -> list[str]:
    data = document(gate)
    mutate(data)
    return list(gate.kb_problems(json.dumps(data)))


def test_the_shipped_table_passes_and_the_check_is_registered(gate: ModuleType) -> None:
    assert gate.check_kb() == []
    assert ("Windows KB invariants", gate.check_kb) in gate.CHECKS


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda d: d.update(schema_version=2), "schema_version"),
        (lambda d: d.update(kb_version="soon"), "kb_version"),
        (lambda d: d["events"].pop("4625"), "required entry 4625"),
        (lambda d: d["logon_types"].pop("10"), "required entry 10"),
        (lambda d: d["statuses"].pop("0xC000006D"), "required entry 0xC000006D"),
        (lambda d: d.pop("events"), "events is missing"),
        (lambda d: d["events"].update({"4625": "x"}), "not an object"),
        (lambda d: d["events"]["4625"].pop("source"), "source is missing"),
        (lambda d: d["events"]["4625"].update(meaning=""), "meaning is missing"),
        (lambda d: d["events"]["4625"].update(aliases=[]), "aliases are missing"),
        (lambda d: d["events"]["4625"].update(aliases=["Logoff"]), "alias 'logoff' names"),
        (
            lambda d: d["statuses"]["0xC0000072"]["aliases"].append("Bad Password"),
            "alias 'Bad Password' names",
        ),
        (lambda d: d["patterns"].pop("window_seconds"), "window_seconds"),
        (lambda d: d["patterns"].pop("brute_force"), "patterns.brute_force"),
        (lambda d: d["patterns"]["undetermined"].pop("meaning"), "patterns.undetermined"),
        (lambda d: d.update(patterns=[]), "patterns are missing"),
        (lambda d: d.update(about="write to " + "x" + "@" + "example.com"), "email-shaped"),
    ],
)
def test_each_invariant_is_enforced(gate: ModuleType, mutate: Any, expected: str) -> None:
    problems = problems_after(gate, mutate)
    assert any(expected in problem for problem in problems), problems


def test_the_same_alias_in_two_different_tables_is_allowed(gate: ModuleType) -> None:
    # "locked out" names status 0xC0000234 and could name an event as well: contradictions are
    # compared inside one table only.
    problems = problems_after(gate, lambda d: d["events"]["4740"]["aliases"].append("locked out"))
    assert problems == []


def test_a_duplicate_code_in_the_file_is_refused(gate: ModuleType) -> None:
    text = gate.KB_FILE.read_text(encoding="utf-8")
    broken = text.replace('"4625": {', '"4624": {', 1)
    assert any("unique keys" in p for p in gate.kb_problems(broken))


def test_not_json_and_not_an_object_are_refused(gate: ModuleType) -> None:
    assert any("not valid JSON" in p for p in gate.kb_problems("{oops"))
    assert gate.kb_problems("[]") == ["windows_kb.json is not an object"]
