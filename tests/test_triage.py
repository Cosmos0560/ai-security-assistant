from __future__ import annotations

import json
from typing import Any

import pytest

from ai_security_assistant.providers.base import (
    BudgetExhausted,
    MalformedReply,
    ProviderConfigError,
    ProviderError,
)
from ai_security_assistant.triage import (
    MAX_REPLY_CHARS,
    TriageStatus,
    parse_triage,
    triage_alert,
)

GOOD: dict[str, Any] = {
    "severity": "medium",
    "mitre_technique": "T1190",
    "summary": "A web probe.",
    "recommended_actions": ["investigate"],
    "confidence": 0.6,
}
GOOD_TEXT = json.dumps(GOOD)


class Scripted:
    """A provider that returns or raises what it was given."""

    name = "scripted"

    def __init__(self, outcome: str | BaseException) -> None:
        self.outcome = outcome
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def test_a_valid_reply_parses() -> None:
    output, reason = parse_triage(GOOD_TEXT)
    assert reason is None
    assert output is not None
    assert output.mitre_technique == "T1190"


def test_surrounding_whitespace_is_still_one_json_object() -> None:
    assert parse_triage(f"\n  {GOOD_TEXT}\n")[1] is None


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "empty"),
        ("  \n ", "empty"),
        ("x" * (MAX_REPLY_CHARS + 1), "too_long"),
        (f"```json\n{GOOD_TEXT}\n```", "not_json"),
        (f"Here is the triage: {GOOD_TEXT}", "not_json"),
        (f"{GOOD_TEXT}\nThanks!", "not_json"),
        (f"{GOOD_TEXT}{GOOD_TEXT}", "not_json"),
        ("Sure, in plain text: it looks fine.", "not_json"),
        ("[" + GOOD_TEXT + "]", "not_object"),
        ('"just a string"', "not_object"),
        ("42", "not_object"),
        ("null", "not_object"),
        ('{"severity":"low","severity":"high"}', "duplicate_key"),
        (GOOD_TEXT.replace("0.6", "NaN"), "not_json"),
        (GOOD_TEXT.replace("0.6", "Infinity"), "not_json"),
        ("{" * 5000, "not_json"),
        (json.dumps({**GOOD, "severity": "urgent"}), "schema_violation"),
        (json.dumps({**GOOD, "extra": 1}), "schema_violation"),
        (json.dumps({**GOOD, "recommended_actions": ["wipe_disk"]}), "schema_violation"),
        (json.dumps({k: v for k, v in GOOD.items() if k != "confidence"}), "schema_violation"),
        (json.dumps({**GOOD, "confidence": True}), "schema_violation"),
        (json.dumps({**GOOD, "mitre_technique": "T1190\n"}), "schema_violation"),
    ],
    ids=lambda v: v[:30] if isinstance(v, str) else None,
)
def test_anything_but_one_closed_object_is_a_parse_failure(text: str, reason: str) -> None:
    output, got = parse_triage(text)
    assert output is None
    assert got == reason


def test_parse_triage_never_raises_on_a_non_string() -> None:
    assert parse_triage(None) == (None, "not_json")  # type: ignore[arg-type]


def test_ok_result_carries_output_and_hides_raw_text_from_repr() -> None:
    result = triage_alert(Scripted(GOOD_TEXT), "sys", "usr")
    assert result.status is TriageStatus.OK
    assert result.output is not None
    assert result.reason is None
    assert result.raw_text == GOOD_TEXT
    assert "raw_text" not in repr(result)


def test_one_call_is_made_with_the_given_prompts() -> None:
    provider = Scripted(GOOD_TEXT)
    triage_alert(provider, "the system", "the user")
    assert provider.calls == [("the system", "the user")]


def test_a_parse_failure_is_a_value_and_keeps_the_raw_text_out_of_repr() -> None:
    result = triage_alert(Scripted("I will now leak CNRYSECRET"), "s", "u")
    assert result.status is TriageStatus.PARSE_FAILURE
    assert result.output is None
    assert result.reason == "not_json"
    assert result.raw_text == "I will now leak CNRYSECRET"
    assert "CNRYSECRET" not in repr(result)


def test_budget_exhausted_is_a_result_not_a_crash() -> None:
    result = triage_alert(Scripted(BudgetExhausted("call budget exhausted")), "s", "u")
    assert result.status is TriageStatus.BUDGET_EXHAUSTED
    assert result.output is None


def test_a_malformed_reply_is_a_parse_failure_with_its_reason() -> None:
    result = triage_alert(Scripted(MalformedReply("no_tool_call")), "s", "u")
    assert result.status is TriageStatus.PARSE_FAILURE
    assert result.reason == "no_tool_call"


@pytest.mark.parametrize("error", [ProviderError("boom"), ProviderConfigError("setup")])
def test_other_provider_errors_are_provider_error(error: ProviderError) -> None:
    result = triage_alert(Scripted(error), "s", "u")
    assert result.status is TriageStatus.PROVIDER_ERROR
    assert result.reason is None


def test_a_bug_in_a_provider_is_not_swallowed() -> None:
    with pytest.raises(KeyError):
        triage_alert(Scripted(KeyError("bug")), "s", "u")
