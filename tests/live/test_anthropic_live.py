"""Live test of the Anthropic provider (D18). NEVER run by the gate or in CI.

It is skipped three ways: the ``live`` marker is deselected by default (``addopts``), it needs
``AISA_LIVE=1``, and it needs ``ANTHROPIC_API_KEY``. A stray key alone cannot spend money. Run it
by hand, on purpose, with the extra installed::

    AISA_LIVE=1 python -m pytest -m live tests/live
"""

from __future__ import annotations

import os

import pytest

from ai_security_assistant.providers.anthropic import AnthropicProvider
from ai_security_assistant.providers.base import CallBudget
from ai_security_assistant.triage import TriageStatus, triage_alert
from tests import golden_cases

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("AISA_LIVE") != "1" or not os.environ.get("ANTHROPIC_API_KEY"),
        reason="live tests need AISA_LIVE=1 and ANTHROPIC_API_KEY",
    ),
]


def test_one_benign_alert_gets_a_schema_valid_triage() -> None:
    budget = CallBudget(1)
    provider = AnthropicProvider(budget)
    result = triage_alert(
        provider, golden_cases.system_prompt(), golden_cases.user_prompt(golden_cases.base_alert())
    )
    assert result.status is TriageStatus.OK
    assert budget.used == 1
