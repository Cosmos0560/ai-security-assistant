from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from ai_security_assistant.schema import (
    MAX_ACTIONS,
    SUMMARY_MAX_CHARS,
    Action,
    Severity,
    TriageOutput,
    tool_input_schema,
)

VALID: dict[str, Any] = {
    "severity": "high",
    "mitre_technique": "T1110.001",
    "summary": "Repeated failed logins.",
    "recommended_actions": ["investigate", "block_ip"],
    "confidence": 0.7,
}


def parse(document: dict[str, Any]) -> TriageOutput:
    """Strict JSON-mode validation, the way triage.py does it."""
    return TriageOutput.model_validate_json(json.dumps(document), strict=True)


def test_a_valid_object_parses() -> None:
    out = parse(VALID)
    assert out.severity is Severity.HIGH
    assert out.recommended_actions == [Action.INVESTIGATE, Action.BLOCK_IP]


@pytest.mark.parametrize("technique", ["T1059", "T1059.001", "T0001"])
def test_technique_forms_accepted(technique: str) -> None:
    parse({**VALID, "mitre_technique": technique})


@pytest.mark.parametrize(
    "technique",
    [
        "T105",
        "T10590",
        "t1059",
        "T1059.01",
        "T1059.0011",
        "T1059\n",
        " T1059",
        "TA0001",
        "1059",
        "",
    ],
)
def test_technique_forms_rejected(technique: str) -> None:
    with pytest.raises(ValidationError):
        parse({**VALID, "mitre_technique": technique})


@pytest.mark.parametrize(
    "change",
    [
        {"severity": "urgent"},
        {"severity": "HIGH"},
        {"summary": ""},
        {"summary": "x" * (SUMMARY_MAX_CHARS + 1)},
        {"recommended_actions": []},
        {"recommended_actions": ["wipe_disk"]},
        {"recommended_actions": ["monitor"] * (MAX_ACTIONS + 1)},
        {"confidence": -0.1},
        {"confidence": 1.1},
        {"confidence": "0.5"},
        {"extra": "key"},
    ],
)
def test_violations_are_rejected(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        parse({**VALID, **change})


@pytest.mark.parametrize("missing", list(VALID))
def test_every_key_is_required(missing: str) -> None:
    document = {k: v for k, v in VALID.items() if k != missing}
    with pytest.raises(ValidationError):
        TriageOutput.model_validate_json(json.dumps(document), strict=True)


def test_summary_at_the_cap_is_accepted() -> None:
    parse({**VALID, "summary": "x" * SUMMARY_MAX_CHARS})


def test_integer_confidence_is_accepted_in_json() -> None:
    out = parse({**VALID, "confidence": 1})
    assert out.confidence == 1.0


def test_tool_schema_has_no_refs_and_matches_the_model() -> None:
    schema = tool_input_schema()
    assert "$ref" not in json.dumps(schema)
    assert "$defs" not in schema
    assert set(schema["properties"]) == set(TriageOutput.model_fields)
    assert set(schema["required"]) == set(TriageOutput.model_fields)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["severity"]["enum"] == [s.value for s in Severity]
    assert schema["properties"]["recommended_actions"]["items"]["enum"] == [a.value for a in Action]


def test_tool_schema_does_not_share_state_with_the_model() -> None:
    first = tool_input_schema()
    snapshot = copy.deepcopy(first)
    first["properties"]["severity"]["enum"].append("x")
    assert tool_input_schema() == snapshot
