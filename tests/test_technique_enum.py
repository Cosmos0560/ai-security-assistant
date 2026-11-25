"""The MITRE allowlist as the ONE source of what a model is told it may answer: the Ollama request
enum, the list in both system prompts, and the validator, which stays the guarantee. The retired
IDs used here are the ones a local model produced when nothing constrained it. No socket is opened.
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterable
from importlib import resources
from typing import Any

import pytest

from ai_security_assistant.detector.canary import new_canary
from ai_security_assistant.eval.dataset import load_windows_dataset
from ai_security_assistant.eval.metrics import technique_allowlisted
from ai_security_assistant.pipeline import (
    AlertOutcome,
    DefenseConfig,
    Status,
    run_alert,
    system_prompt_for,
)
from ai_security_assistant.prompt import (
    NAIVE_PROMPT_VERSION,
    PROMPT_VERSION,
    build_naive_system_prompt,
    build_system_prompt,
)
from ai_security_assistant.providers.base import CallBudget
from ai_security_assistant.providers.ollama import OllamaProvider
from ai_security_assistant.schema import MITRE_ID_PATTERN, tool_input_schema
from ai_security_assistant.validator import mitre
from ai_security_assistant.wrap import new_nonce

RETIRED = ("T1026", "T1206")


def file_entries() -> dict[str, str]:
    """The allowlist as the data file holds it, read independently of the code under test."""
    resource = resources.files("ai_security_assistant").joinpath("data", "mitre_allowlist.json")
    entries: dict[str, str] = json.loads(resource.read_text(encoding="utf-8"))["techniques"]
    return entries


class Replies:
    """A transport that answers ``/api/chat`` with one technique and keeps every request."""

    def __init__(self, technique: str) -> None:
        content = {
            "severity": "medium",
            "mitre_technique": technique,
            "summary": "A logon event.",
            "recommended_actions": ["investigate"],
            "confidence": 0.5,
        }
        body = {"done": True, "done_reason": "stop", "message": {"content": json.dumps(content)}}
        self.body = json.dumps(body).encode()
        self.requests: list[dict[str, Any]] = []

    def __call__(self, request: urllib.request.Request, _timeout: float) -> bytes:
        assert isinstance(request.data, bytes)
        self.requests.append(json.loads(request.data))
        return self.body


def triage(technique: str, config: DefenseConfig) -> tuple[AlertOutcome, Replies]:
    transport = Replies(technique)
    provider = OllamaProvider(CallBudget(1), environ={}, transport=transport)
    canary = new_canary("enum")
    system, _version = system_prompt_for(config, canary)
    outcome = run_alert(
        load_windows_dataset()[0].alert,
        provider,
        config=config,
        system=system,
        canary=canary,
        nonce=new_nonce("enum"),
    )
    return outcome, transport


@pytest.mark.parametrize("config", list(DefenseConfig))
def test_every_request_carries_the_allowlist_as_the_enum(config: DefenseConfig) -> None:
    _outcome, transport = triage("T1110", config)
    (request,) = transport.requests
    properties = request["format"]["properties"]
    assert properties["mitre_technique"] == {"type": "string", "enum": sorted(file_entries())}
    assert set(properties["mitre_technique"]["enum"]) == mitre.allowlist()
    assert not set(RETIRED) & set(properties["mitre_technique"]["enum"])


def test_only_the_technique_property_differs_from_the_tool_schema() -> None:
    plain, narrowed = tool_input_schema(), tool_input_schema(["T1110", "T1003"])
    assert plain["properties"]["mitre_technique"]["pattern"] == MITRE_ID_PATTERN
    assert "enum" not in plain["properties"]["mitre_technique"]  # Anthropic's schema is unchanged
    assert narrowed["properties"]["mitre_technique"]["enum"] == ["T1003", "T1110"]
    for schema in (plain, narrowed):
        del schema["properties"]["mitre_technique"]
    assert plain == narrowed


@pytest.mark.parametrize("technique", [*RETIRED, "T1026.001", "T9999"])
@pytest.mark.parametrize("config", [DefenseConfig.VALIDATOR_ONLY, DefenseConfig.ALL])
def test_a_reply_outside_the_enum_is_still_rejected(technique: str, config: DefenseConfig) -> None:
    """The enum only narrows decoding. A server that ignores it is still caught by check 3."""
    outcome, _transport = triage(technique, config)
    assert outcome.status is Status.NEEDS_HUMAN_REVIEW
    assert outcome.reasons == ("mitre.not_allowlisted",)
    assert outcome.verdict is None


@pytest.mark.parametrize("build", [build_system_prompt, build_naive_system_prompt])
def test_both_system_prompts_list_every_technique_with_its_name(
    build: Any,
) -> None:
    prompt = build(new_canary("enum"))
    listed = prompt.split("any other ID is rejected:\n", 1)[1].strip().split("\n")
    assert listed == [f"{i} {name}" for i, name in file_entries().items()]


def test_the_prompt_versions_were_bumped_for_the_list() -> None:
    assert (PROMPT_VERSION, NAIVE_PROMPT_VERSION) == ("3", "naive-2")


def test_the_allowlist_has_one_source() -> None:
    names = mitre.techniques()
    assert names == file_entries() and mitre.allowlist() == frozenset(names)
    names.clear()  # a copy: a caller cannot change what the validator accepts
    assert mitre.techniques() == file_entries()


def test_the_allowlisted_share_is_counted_from_the_replies() -> None:
    def outcomes() -> Iterable[AlertOutcome]:
        for technique in ("T1110", "T1110.003", *RETIRED):
            yield triage(technique, DefenseConfig.NONE)[0]  # the validator is off

    listed = list(outcomes())
    assert all(o.status is Status.TRIAGED for o in listed)
    no_reply = AlertOutcome(listed[0].alert, Status.NEEDS_HUMAN_REVIEW, None, (), None, True)
    assert technique_allowlisted([*listed, no_reply]).to_json() == {"n": 2, "of": 4}
    assert technique_allowlisted([]).to_json() == {"n": 0, "of": 0}
