"""Phase 6 gate checks: dataset invariants (PLAN section 6 item 7) and the README metrics drift
check (D25). Email-shaped strings are built at runtime from parts (D30)."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from types import ModuleType
from typing import Any

import pytest

from ai_security_assistant.eval import dataset

AT = "@"


def real_text(gate: ModuleType) -> str:
    text: str = gate.DATASET.read_bytes().decode("utf-8")
    return text


def rows(gate: ModuleType) -> list[dict[str, Any]]:
    return [json.loads(line) for line in real_text(gate).split("\n") if line.strip()]


def dump(items: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in items)


def first(items: list[dict[str, Any]], **match: object) -> dict[str, Any]:
    return next(r for r in items if all(r.get(k) == v for k, v in match.items()))


def test_the_gate_lists_match_the_eval_package(gate: ModuleType) -> None:
    assert gate.DATASET_CATEGORIES == dataset.CATEGORIES
    assert gate.DATASET_GOALS == dataset.ATTACK_GOALS
    assert len(gate.DATASET_GOALS) == 6


def test_the_real_dataset_passes(gate: ModuleType) -> None:
    assert gate.check_dataset() == []


def test_both_phase6_checks_run_in_the_gate(gate: ModuleType) -> None:
    checks = [check for _name, check in gate.CHECKS]
    assert gate.check_dataset in checks and gate.check_readme_metrics in checks
    assert checks.index(gate.check_dataset) < checks.index(gate.check_readme_metrics)


def test_the_drift_check_runs_the_readme_module(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []

    def fake_run_tool(args: list[str]) -> list[str]:
        seen.append(list(args))
        return ["exit code 1"]

    monkeypatch.setattr(gate, "run_tool", fake_run_tool)
    assert gate.check_readme_metrics() == ["exit code 1"]
    (args,) = seen
    assert args[1:4] == ["-m", "ai_security_assistant.eval.readme_table", "--check"]
    assert args[4].endswith("README.md")


# ---------------------------------------------------------------- value rules per string


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("from 10.0.0.1", "IPv4 outside RFC 5737"),
        ("from 999.1.1.1", "invalid IPv4-shaped value"),
        ("from fe80::1", "IPv6 outside 2001:db8::/32"),
        ("callback to evil.com", "domain other than example.com or .test"),
        ("callback to example.org", "domain other than example.com or .test"),
        ("md5 d41d8cd98f00b204e9800998ecf8427e", "hash-shaped value that is not obviously fake"),
        ("x " + base64.b64encode(b"some other decoded text").decode(), "encoded blob"),
        ("".join(f"\\x{b:02x}" for b in b"other text"), "encoded blob"),
        ("".join(f"%{b:02X}" for b in b"other text"), "encoded blob"),
        ("\\xff\\xfe\\xfd\\xfc", "encoded blob"),
        ("%FF%FE%FD%FC", "encoded blob"),
    ],
)
def test_a_bad_value_is_caught(gate: ModuleType, text: str, problem: str) -> None:
    assert any(p.startswith(problem) for p in gate.string_problems(text)), gate.string_problems(
        text
    )


def test_an_email_shaped_string_is_caught(gate: ModuleType) -> None:
    assert gate.string_problems("user " + "svc" + AT + "corp.example.test") == [
        "email-shaped string"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "192.0.2.1 198.51.100.255 203.0.113.7 2001:db8::5 at 09:06:10",
        "web01.example.test storage.example.com example.com a.b.example.com",
        "powershell.exe invoice.zip index.php /etc/passwd Mozilla/5.0 curl/8.4.0",
        "0000000000000000000000000000004c " + "abcdef01" * 8 + " " + "ab" * 20,
        "request_id=" + base64.b64encode(b"req-2026-08-10-001").decode(),
        "AAAAAAAAAAAAAAAAAAAA a long hexadecimal-free plain sentence",
    ],
)
def test_allowed_values_pass(gate: ModuleType, text: str) -> None:
    assert gate.string_problems(text) == []


# ---------------------------------------------------------------- whole-file rules


Mutation = Callable[[list[dict[str, Any]]], None]


def drop_one_injection(items: list[dict[str, Any]]) -> None:
    items.remove(first(items, label="injection", category="direct_override"))


def benign_with_category(items: list[dict[str, Any]]) -> None:
    first(items, label="benign")["category"] = "role_play"


def unknown_goal(items: list[dict[str, Any]]) -> None:
    first(items, label="injection")["attack_goal"] = "make_coffee"


def unknown_category(items: list[dict[str, Any]]) -> None:
    first(items, label="injection")["category"] = "made_up"


def unknown_label(items: list[dict[str, Any]]) -> None:
    first(items, label="benign")["label"] = "unsure"


def move_split(items: list[dict[str, Any]]) -> None:
    first(items, label="benign", split="dev")["split"] = "heldout"


def too_few_hard_negatives(items: list[dict[str, Any]]) -> None:
    for row in items:
        row["hard_negative"] = False


def one_goal_missing(items: list[dict[str, Any]]) -> None:
    for row in items:
        if row["attack_goal"] == "non_json":
            row["attack_goal"] = "canary_leak"


def real_ip(items: list[dict[str, Any]]) -> None:
    first(items, label="benign")["record"]["extra"] = "seen from 172.16.0.5"


def blob_removed(items: list[dict[str, Any]]) -> None:
    encoded = base64.b64encode(b"test-trace-001").decode()
    for row in items:
        if encoded in json.dumps(row["record"]):
            items.remove(row)
            break


@pytest.mark.parametrize(
    ("mutation", "problem"),
    [
        (drop_one_injection, "class counts"),
        (benign_with_category, "benign sample with a category or goal"),
        (unknown_goal, "injection without a known attack_goal"),
        (unknown_category, "injection without a known category"),
        (unknown_label, "unknown label"),
        (move_split, "benign/dev count is not 36"),
        (too_few_hard_negatives, "only 0 hard negatives"),
        (one_goal_missing, "attack goals used"),
        (real_ip, "IPv4 outside RFC 5737"),
        (blob_removed, "harmless-list entry matches no blob"),
    ],
)
def test_a_broken_dataset_is_caught(gate: ModuleType, mutation: Mutation, problem: str) -> None:
    items = rows(gate)
    mutation(items)
    problems = gate.dataset_problems(dump(items))
    assert any(problem in p for p in problems), problems


def test_a_category_outside_7_to_8_is_caught(gate: ModuleType) -> None:
    items = rows(gate)
    donor = first(items, label="injection", category="role_play")
    donor["category"] = "direct_override"  # direct_override: 8 -> 9, role_play: 8 -> 7
    problems = gate.dataset_problems(dump(items))
    assert "category direct_override has 9 samples" in problems
    assert not any("role_play" in p for p in problems)


def test_lines_that_are_not_objects_are_caught(gate: ModuleType) -> None:
    problems = gate.dataset_problems("{oops\n[1, 2]\n")
    assert problems[:2] == ["line 1: not JSON", "line 2: not an object"]


def test_crlf_is_read_like_lf(gate: ModuleType) -> None:
    assert gate.dataset_problems(real_text(gate).replace("\n", "\r\n")) == []
