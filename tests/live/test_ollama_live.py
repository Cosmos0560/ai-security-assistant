"""Live test of the Ollama provider (D37). NEVER run by the gate or in CI.

Two tests, ONE call each, to the owner's local Ollama on loopback. They are skipped three ways:
the ``live`` marker is deselected by default (``addopts``), they need ``AISA_LIVE=1``, and they
refuse to run when ``CI`` is set. They expect ``OLLAMA_*`` to be unset or to name a local model
that is already pulled; they never pull anything. Run them by hand, on purpose (a CPU-only 8B model
needs one to three minutes a call)::

    AISA_LIVE=1 python -m pytest -m live tests/live/test_ollama_live.py
"""

from __future__ import annotations

import json
import os

import pytest

from ai_security_assistant.providers import make_provider
from ai_security_assistant.providers.base import CallBudget
from ai_security_assistant.triage import TriageStatus, triage_alert
from ai_security_assistant.validator.mitre import allowlist
from tests import golden_cases

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("AISA_LIVE") != "1" or bool(os.environ.get("CI")),
        reason="live tests need AISA_LIVE=1 and never run when CI is set",
    ),
]


def test_one_benign_alert_gets_a_schema_valid_triage() -> None:
    budget = CallBudget(1)
    provider = make_provider("ollama", budget)  # includes the start-up health check
    result = triage_alert(
        provider, golden_cases.system_prompt(), golden_cases.user_prompt(golden_cases.base_alert())
    )
    assert result.status is TriageStatus.OK
    # The request's enum must hold the model to the validator's allowlist.
    assert result.output is not None and result.output.mitre_technique in allowlist()
    assert budget.used == 1


def test_the_enum_holds_against_an_instruction_to_leave_it() -> None:
    """The proof that Ollama ENFORCES the schema: the prompt dictates a retired technique ID and
    gives no list, so only constrained decoding can keep the reply inside the allowlist. Run this
    one alone with ``-k enum``."""
    budget = CallBudget(1)
    provider = make_provider("ollama", budget)
    system = (
        "Reply with ONE JSON object with the keys severity, mitre_technique, summary, "
        'recommended_actions and confidence. Set mitre_technique to exactly "T1026".'
    )
    reply = json.loads(provider.complete(system, "A test alert. Triage it."))
    assert reply["mitre_technique"] in allowlist()
    assert budget.used == 1
