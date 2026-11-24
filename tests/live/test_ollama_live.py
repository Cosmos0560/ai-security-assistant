"""Live test of the Ollama provider (D37). NEVER run by the gate or in CI.

One call to the owner's local Ollama on loopback. It is skipped three ways: the ``live`` marker is
deselected by default (``addopts``), it needs ``AISA_LIVE=1``, and it refuses to run when ``CI`` is
set. It expects ``OLLAMA_*`` to be unset or to name a local model that is already pulled; it never
pulls anything. Run it by hand, on purpose (a CPU-only 8B model needs one to three minutes)::

    AISA_LIVE=1 python -m pytest -m live tests/live/test_ollama_live.py
"""

from __future__ import annotations

import os

import pytest

from ai_security_assistant.providers import make_provider
from ai_security_assistant.providers.base import CallBudget
from ai_security_assistant.triage import TriageStatus, triage_alert
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
    assert budget.used == 1
