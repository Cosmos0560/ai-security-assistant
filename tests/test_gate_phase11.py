"""Phase 11 gate check: the Windows-auth eval set invariants (D43). Email-shaped strings are
built at runtime from parts (D30)."""

from __future__ import annotations

import json
from collections.abc import Callable
from types import ModuleType
from typing import Any

import pytest

from ai_security_assistant.eval import dataset
from ai_security_assistant.schema import Severity

AT = "@"
Rows = list[dict[str, Any]]


def rows(gate: ModuleType) -> Rows:
    text = gate.WINDOWS_DATASET.read_bytes().decode("utf-8")
    return [json.loads(line) for line in text.split("\n") if line.strip()]


def kb(gate: ModuleType) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(gate.KB_FILE.read_bytes())
    return document


def problems(gate: ModuleType, items: Rows) -> list[str]:
    text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in items)
    found: list[str] = gate.windows_dataset_problems(text, kb(gate))
    return found


def in_group(items: Rows, group: str) -> Rows:
    return [r for r in items if r["group"] == group]


def eventdata(row: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = row["record"]["data"]["win"]["eventdata"]
    return data


def test_the_gate_lists_match_the_eval_package(gate: ModuleType) -> None:
    assert tuple(gate.WINDOWS_GROUP_COUNTS) == dataset.WINDOWS_GROUPS
    assert set(gate.WINDOWS_GOAL_COUNTS) <= set(dataset.WINDOWS_GOALS)
    assert tuple(s.value for s in Severity) == gate.WINDOWS_SEVERITIES
    assert gate.WINDOWS_BLIND_SPOTS == dataset.KNOWN_MISSES


def test_the_real_set_passes_and_the_check_runs(gate: ModuleType) -> None:
    assert gate.check_windows_dataset() == []
    assert gate.check_windows_dataset in [check for _name, check in gate.CHECKS]


Change = Callable[[Rows], object]


def set_data(group: str, key: str, value: str) -> Change:
    return lambda items: eventdata(in_group(items, group)[0]).update({key: value})


def set_row(group: str, key: str, value: object) -> Change:
    return lambda items: in_group(items, group)[0].update({key: value})


def set_record(group: str, key: str, value: object) -> Change:
    return lambda items: in_group(items, group)[0]["record"].update({key: value})


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (set_data("single", "ipAddress", "10.0.0.1"), "ipAddress outside RFC 5737"),
        (set_data("single", "ipAddress", "host"), "ipAddress is not an address"),
        (set_data("single", "targetUserName", "jsmith"), "generic test name"),
        (set_data("single", "targetUserName", "x" + AT + "example.com"), "email-shaped"),
        (set_data("injection", "subjectUserName", "jsmith"), "generic test name"),
        (set_record("single", "location", "from 127.0.0.1"), "IPv4 outside RFC 5737"),
        (set_record("single", "location", "evil.com"), "domain other than"),
        (set_record("single", "full_log", "typed by hand"), "not the KB event name"),
        (set_data("brute_force", "logonType", "6"), "logon type not in the KB"),
        (set_data("brute_force", "status", "0xc000dead"), "status not in the KB"),
        (set_data("brute_force", "subStatus", "0xc000dead"), "subStatus not in the KB"),
        (
            lambda items: items[0]["record"]["data"]["win"]["system"].update(eventID="9999"),
            "event ID not in the KB",
        ),
        (set_row("single", "expected_technique", "brute"), "expected_technique label"),
        (set_row("single", "expected_technique", None), "expected_technique label"),
        (set_row("single", "expected_min_severity", "bad"), "expected_min_severity label"),
        (set_row("spraying", "expected_technique", "T1110"), "differs from the KB technique"),
        (set_row("distributed_spraying", "known_miss", None), "known_miss"),
        (set_row("single", "known_miss", "distributed_spraying"), "known_miss"),
        (set_row("injection", "attack_goal", "canary_leak"), "goal counts"),
        (lambda items: items.remove(in_group(items, "single")[0]), "group counts"),
        (lambda items: items.remove(in_group(items, "single")[6]), "no sample of event 4720"),
        (set_data("spraying", "ipAddress", "198.51.100.99"), "group spraying does not"),
        (set_data("brute_force", "targetUserName", "user99"), "group brute_force does not"),
        (set_data("distributed_spraying", "ipAddress", "203.0.113.12"), "distributed_spraying"),
        (set_data("low_and_slow_spraying", "ipAddress", "203.0.113.9"), "low_and_slow_spraying"),
        (
            lambda items: [
                eventdata(r).update(targetUserName=f"user{i}9")
                for i, r in enumerate(in_group(items, "undetermined_5_users"))
            ],
            "group undetermined_5_users does not",
        ),
    ],
)
def test_each_broken_invariant_is_reported(gate: ModuleType, change: Change, problem: str) -> None:
    items = rows(gate)
    change(items)
    assert any(problem in found for found in problems(gate, items)), problems(gate, items)


def test_a_missing_status_and_group_are_reported(gate: ModuleType) -> None:
    items = [
        r
        for r in rows(gate)
        if r["group"] != "spraying" and eventdata(r).get("status") != "0xc0000234"
    ]
    found = problems(gate, items)
    assert "group spraying has no events" in found
    assert "no sample of status 0XC0000234" in found


def test_a_line_that_is_not_a_row_is_reported(gate: ModuleType) -> None:
    for text in ("not json\n", "[]\n", "{}\n", '{"group": "single", "record": 1}\n'):
        found = gate.windows_dataset_problems(text, kb(gate))
        assert "line 1: not a Windows-set row" in found, text


def test_loopback_is_allowed_as_an_address_only(gate: ModuleType) -> None:
    assert gate._windows_ip_problems("127.0.0.1") == []
    assert gate._windows_ip_problems("::1") == []
    assert gate._windows_ip_problems("-") == []
    assert gate._windows_ip_problems("127.0.0.2") != []
