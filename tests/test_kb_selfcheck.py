"""The KB self-consistency invariant (Phase 10): every entry's own reference text passes check 9,
quoted and as a plain claim; the gate runs it as a module."""

from __future__ import annotations

import json
from importlib import resources
from types import ModuleType
from typing import Any

import pytest

from ai_security_assistant.kb import KnowledgeBase, load_kb, parse_kb, selfcheck


def kb_with(mutate: Any) -> KnowledgeBase:
    text = resources.files("ai_security_assistant").joinpath("data", "windows_kb.json")
    document = json.loads(text.read_text(encoding="utf-8"))
    mutate(document)
    return parse_kb(json.dumps(document))


def test_the_shipped_table_is_self_consistent() -> None:
    assert selfcheck.problems(load_kb()) == []


def test_every_entry_is_probed_and_statuses_twice() -> None:
    kb = load_kb()
    facts = list(selfcheck._facts(kb))
    assert len(facts) == len(kb.events) + len(kb.logon_types) + 2 * len(kb.statuses)
    line = selfcheck.reference_line(facts[0], kb.kb_version)
    assert line.startswith("Event ") and kb.events[facts[0].code].meaning in line


def test_a_meaning_that_names_another_code_fails_as_a_plain_claim() -> None:
    def cross_code(document: dict[str, Any]) -> None:
        entry = document["statuses"]["0xC000006D"]
        entry["meaning"] += " For example 0xC0000064."

    found = selfcheck.problems(kb_with(cross_code))
    assert found == [
        "status 0xC000006D: its reference text as a plain claim fails ['ungrounded_status']",
        "sub_status 0xC000006D: its reference text as a plain claim fails ['ungrounded_status']",
    ]


def test_a_meaning_with_another_entrys_alias_fails_as_a_plain_claim() -> None:
    def other_alias(document: dict[str, Any]) -> None:
        network = document["logon_types"]["3"]["aliases"][0]
        document["logon_types"]["8"]["meaning"] = f"A user logged on over the {network}."

    assert selfcheck.problems(kb_with(other_alias)) == [
        "logon_type 8: its reference text as a plain claim fails ['contradiction_logon_type']"
    ]


def test_main_reports_and_sets_the_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert selfcheck.main() == 0
    assert "passes check 9" in capsys.readouterr().out
    monkeypatch.setattr(selfcheck, "problems", lambda _kb: ["x: broken"])
    assert selfcheck.main() == 1
    assert capsys.readouterr().out == "x: broken\n"


def test_the_gate_runs_the_self_check_after_the_kb_invariants(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    checks = [check for _name, check in gate.CHECKS]
    assert checks.index(gate.check_kb) + 1 == checks.index(gate.check_kb_selfcheck)
    seen: list[list[str]] = []

    def fake_run_tool(args: list[str]) -> list[str]:
        seen.append(list(args))
        return ["exit code 1"]

    monkeypatch.setattr(gate, "run_tool", fake_run_tool)
    assert gate.check_kb_selfcheck() == ["exit code 1"]
    assert seen == [[gate.sys.executable, "-m", "ai_security_assistant.kb.selfcheck"]]
