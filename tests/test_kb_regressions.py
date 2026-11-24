"""Phase 10 regressions: the two recorded local-model hallucinations, the PLAN section 11.4
cases and the owner's positive cases, each with its exact check-9 reason code.

The recorded replies are replayed through ``OllamaProvider`` with a fake transport (no socket,
no Ollama). Windows names, meanings and aliases in the synthetic cases are read from
``data/windows_kb.json``; only codes appear as literals. Text that claims a password is built at
runtime.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ai_security_assistant.detector.canary import new_canary
from ai_security_assistant.kb import PatternFact, load_kb
from ai_security_assistant.models import Alert
from ai_security_assistant.pipeline import DefenseConfig, Status, run_pipeline
from ai_security_assistant.prompt import build_user_prompt
from ai_security_assistant.providers.base import CallBudget
from ai_security_assistant.providers.mock import WellBehavedMock
from ai_security_assistant.providers.ollama import OllamaProvider
from ai_security_assistant.sanitize import sanitize_alert
from ai_security_assistant.triage import TriageResult, TriageStatus, parse_triage
from ai_security_assistant.validator import Verdict, validate
from ai_security_assistant.validator.kb import scan
from ai_security_assistant.wrap import new_nonce

FIXTURES = Path(__file__).parent / "fixtures" / "ollama"
EXCERPT = "chat_hallucination_4625.json"
REAL = "chat_real_status_logon.json"
KB = load_kb()
EVENTS, LOGON, STATUS = KB.events, KB.logon_types, KB.statuses
NOUN = EVENTS["4625"].never_records[0].split()[-1]
NOW = datetime(2026, 8, 10, 9, 0, 0, tzinfo=UTC)
CANARY = new_canary("s")


def alert(**fields: Any) -> Alert:
    base: dict[str, Any] = {
        "source": "wazuh",
        "timestamp": NOW,
        "id": "a-1",
        "rule_id": "60122",
        "severity_raw": "5",
    }
    return Alert(**{**base, **fields})


# The alert both recordings describe: a failed RDP logon, generic Status with the bad-password
# Sub Status (the real capture names exactly these codes).
REPLAY = alert(
    event_id="4625",
    logon_type="10",
    status="0xc000006d",
    sub_status="0xc000006a",
    src_ip_raw="192.0.2.66",
    target_user="admin-test",
)


def content(name: str) -> str:
    body = json.loads((FIXTURES / name).read_bytes())
    text = body["message"]["content"]
    assert isinstance(text, str)
    return text


class Replay:
    """A transport that answers ``/api/chat`` with one recorded body."""

    def __init__(self, name: str) -> None:
        self.body = (FIXTURES / name).read_bytes()
        self.calls = 0

    def __call__(self, _request: object, _timeout: float) -> bytes:
        self.calls += 1
        return self.body


# ---------------------------------------------------------------- the recorded hallucinations

EXCERPT_LINES = content(EXCERPT).splitlines()


@pytest.mark.parametrize(
    ("index", "expected", "claim"),
    [
        (0, ["ungrounded_logon_type", "contradiction_logon_type"], "Logon Type 10 as Interactive"),
        (1, ["contradiction_status"], "0xC000006A as 'not granted the requested logon right'"),
        (2, [], "'Different passwords are tried': passes on its own (blind spot, pinned)"),
        (3, [], "lockout as 'logon right not granted', no code near it (D42 blind spot)"),
        (4, ["contradiction_status"], "0xC000006D as a bare 'Incorrect password'"),
    ],
)
def test_each_claim_of_the_recorded_excerpt(index: int, expected: list[str], claim: str) -> None:
    assert scan([EXCERPT_LINES[index]], REPLAY) == expected, claim


def test_the_excerpt_lines_are_the_recorded_ones() -> None:
    assert len(EXCERPT_LINES) == 5
    assert "10 for" in EXCERPT_LINES[0] and "Interactive" in EXCERPT_LINES[0]
    assert "0xC000006A" in EXCERPT_LINES[1]
    assert all("0x" not in EXCERPT_LINES[i] for i in (2, 3))  # no code near either claim


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("status_meaning", ["contradiction_status"]),  # 0xC000006A as "account does not exist"
        ("logon_type_10", ["contradiction_logon_type"]),  # Logon Type 10 as "a network logon"
    ],
)
def test_each_claim_of_the_real_capture(key: str, expected: list[str]) -> None:
    reply = json.loads(content(REAL))
    assert scan([reply[key]], REPLAY) == expected


def test_the_real_capture_needs_the_back_reference_sentence() -> None:
    """The wrong meaning sits in the sentence AFTER the code ("This error code corresponds to
    ... the account does not exist"); the code's own sentence alone says nothing wrong."""
    text = json.loads(content(REAL))["status_meaning"]
    first_sentence = text[: text.index(". ") + 1]
    assert "0xC000006A" in first_sentence
    assert scan([first_sentence], REPLAY) == []
    assert scan([text], REPLAY) == ["contradiction_status"]


@pytest.mark.parametrize(
    ("fixture", "schema_reason", "kb_reasons"),
    [
        (
            EXCERPT,
            "schema.not_json",
            {"kb.ungrounded_logon_type", "kb.contradiction_logon_type", "kb.contradiction_status"},
        ),
        (
            REAL,
            "schema.schema_violation",
            {"kb.contradiction_status", "kb.contradiction_logon_type"},
        ),
    ],
)
@pytest.mark.parametrize("config", [DefenseConfig.ALL, DefenseConfig.VALIDATOR_ONLY])
def test_the_recorded_replies_end_in_review_through_the_ollama_provider(
    fixture: str, schema_reason: str, kb_reasons: set[str], config: DefenseConfig
) -> None:
    transport = Replay(fixture)
    budget = CallBudget(1)
    provider = OllamaProvider(budget, environ={}, transport=transport)
    result = run_pipeline([REPLAY], provider, budget, config=config, seed="s")
    (outcome,) = result.outcomes
    assert transport.calls == 1
    assert outcome.status is Status.NEEDS_HUMAN_REVIEW
    assert outcome.verdict is None
    assert schema_reason in outcome.reasons
    assert {reason for reason in outcome.reasons if reason.startswith("kb.")} == kb_reasons


# ---------------------------------------------------------------- PLAN section 11.4 regressions


def test_logon_type_10_named_interactive_fails_and_remote_interactive_passes() -> None:
    subject = alert(logon_type="10")
    assert scan([f"logon type 10 ({LOGON['2'].name})"], subject) == ["contradiction_logon_type"]
    assert scan([f"logon type 10 ({LOGON['10'].name})"], subject) == []


def test_wrong_password_status_named_logon_type_not_granted_fails() -> None:
    subject = alert(event_id="4625", status="0xc000006d", sub_status="0xc000006a")
    not_granted = STATUS["0xC000015B"].aliases[0]
    assert scan([f"0xC000006A ... {not_granted}"], subject) == ["contradiction_status"]
    assert scan([f"0xC000006A: {STATUS['0xC000006A'].meaning}"], subject) == []
    assert scan([f"0xC000006A ({STATUS['0xC000006A'].aliases[0]})"], subject) == []


def test_a_lockout_claimed_on_a_wrong_password_alert_is_ungrounded() -> None:
    subject = alert(event_id="4625", status="0xc000006d", sub_status="0xc000006a")
    locked = STATUS["0xC0000234"].aliases[0]
    assert scan([f"status 0xC0000234 ({locked})"], subject) == ["ungrounded_status"]


def test_lockout_wording_where_the_table_allows_it() -> None:
    lockout_event = EVENTS["4740"].aliases[0]
    assert scan([f"Event 4740: {lockout_event}"], alert(event_id="4740")) == []
    locked = STATUS["0xC0000234"].aliases[1]
    assert (
        scan(
            [f"event 4625 with 0xC0000234 ({locked})"], alert(event_id="4625", status="0xc0000234")
        )
        == []
    )
    # ...but the 4740 entry's own alias right after "event 4625" is a contradiction.
    assert scan([f"event 4625 ({lockout_event})"], alert(event_id="4625")) == [
        "contradiction_event_id"
    ]


def test_the_attempted_password_claim_fails_on_a_4625_alert() -> None:
    claim = "The attempted " + NOUN + " was " + "Winter" + "2026"
    assert scan([claim], alert(event_id="4625")) == ["not_recorded_claim"]


@pytest.mark.parametrize(
    ("group", "accepted", "rejected", "code"),
    [
        ("password_spraying", "T1110.003", "T1110.001", "contradiction_pattern"),
        ("brute_force", "T1110.001", "T1110.003", "contradiction_pattern"),
        ("undetermined", "T1110", "T1110.003", "unsupported_pattern"),
        ("undetermined", "T1110", "T1110.001", "unsupported_pattern"),
    ],
)
def test_the_technique_against_the_d41_group(
    group: str, accepted: str, rejected: str, code: str
) -> None:
    rule = getattr(KB.patterns, group)
    pattern = PatternFact(group, getattr(rule, "technique", None), rule.meaning, 3600, 4, 1, 4)  # type: ignore[arg-type]
    subject = alert(event_id="4625")
    assert scan([], subject, technique=accepted, pattern=pattern) == []
    assert scan([], subject, technique=rejected, pattern=pattern) == [code]


def test_the_table_techniques_are_the_ones_the_plan_names() -> None:
    assert KB.patterns.password_spraying.technique == "T1110.003"
    assert KB.patterns.brute_force.technique == "T1110.001"


@pytest.mark.parametrize(
    "text", ["RDP on port 3389 since 2026", "4625 failures, rule 60122, 1786266370"]
)
def test_a_bare_port_or_year_is_not_an_event_id(text: str) -> None:
    assert scan([text], alert()) == []


# ---------------------------------------------------------------- the owner's positive cases


def accepted_reply(subject: Alert, summary: str) -> TriageResult:
    sanitized, _report = sanitize_alert(subject)
    user = build_user_prompt(sanitized, new_nonce("s"), None)
    document = json.loads(WellBehavedMock(CallBudget(1)).complete("s", user))
    raw = json.dumps({**document, "summary": summary})
    output, reason = parse_triage(raw)
    assert output is not None, reason
    return TriageResult(TriageStatus.OK, output=output, raw_text=raw)


POSITIVE = [
    (
        "4625 with 0xC0000234 ({locked})",
        {"event_id": "4625", "status": "0xc0000234"},
    ),
    ("Logon Type 10 ({remote} / {rdp})", {"logon_type": "10"}),
    (
        "Status 0xC000006D with Sub Status 0xC000006A ({bad})",
        {"status": "0xc000006d", "sub_status": "0xc000006a"},
    ),
    ("4740 {lockout_event}", {"event_id": "4740"}),
    ("RDP from port 3389, first seen in 2026", {"event_id": "4624", "logon_type": "10"}),
    ("the attacker is trying different {noun}s", {"event_id": "4625"}),
]
WORDS = {
    "locked": STATUS["0xC0000234"].aliases[1],
    "remote": LOGON["10"].name,
    "rdp": LOGON["10"].aliases[3],
    "bad": STATUS["0xC000006A"].aliases[0],
    "lockout_event": EVENTS["4740"].aliases[0],
    "noun": NOUN,
}


@pytest.mark.parametrize(("template", "fields"), POSITIVE)
def test_the_positive_cases_are_accepted_by_the_whole_validator(
    template: str, fields: dict[str, str]
) -> None:
    subject = alert(**fields)
    summary = template.format(**WORDS)
    assert scan([summary], subject) == []
    checked = validate(accepted_reply(subject, summary), subject, CANARY)
    assert checked.verdict is Verdict.ACCEPTED, checked.reasons


def test_the_positive_words_are_the_ones_the_owner_named() -> None:
    """The templates read the table; this pins that they picked the intended entries."""
    assert WORDS["locked"] in STATUS["0xC0000234"].aliases
    assert WORDS["rdp"] in LOGON["10"].aliases and WORDS["remote"] == LOGON["10"].name
    assert WORDS["bad"] in STATUS["0xC000006A"].aliases
    assert WORDS["lockout_event"] in EVENTS["4740"].aliases
