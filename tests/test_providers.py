from __future__ import annotations

import subprocess
import sys

import pytest

from ai_security_assistant.providers import PROVIDER_NAMES, make_provider
from ai_security_assistant.providers.base import (
    BudgetExhausted,
    CallBudget,
    MalformedReply,
    Provider,
    ProviderConfigError,
    ProviderError,
)
from ai_security_assistant.providers.mock import NaiveMock, WellBehavedMock
from tests import golden_cases

# ---------------------------------------------------------------- CallBudget


def test_budget_counts_and_then_refuses() -> None:
    budget = CallBudget(2)
    assert (budget.used, budget.remaining, budget.max_calls) == (0, 2, 2)
    budget.spend()
    budget.spend()
    assert (budget.used, budget.remaining) == (2, 0)
    with pytest.raises(BudgetExhausted):
        budget.spend()
    assert budget.used == 2  # a refused spend is not counted


def test_a_zero_budget_refuses_at_once() -> None:
    with pytest.raises(BudgetExhausted):
        CallBudget(0).spend()


@pytest.mark.parametrize("bad", [-1, 1.5, "3", None, True])
def test_a_bad_budget_is_refused(bad: object) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        CallBudget(bad)  # type: ignore[arg-type]


def test_budget_repr_shows_counts_only() -> None:
    budget = CallBudget(5)
    budget.spend()
    assert repr(budget) == "CallBudget(used=1, max_calls=5)"


def test_the_error_hierarchy() -> None:
    assert issubclass(BudgetExhausted, ProviderError)
    assert issubclass(MalformedReply, ProviderError)
    assert issubclass(ProviderConfigError, ProviderError)
    assert MalformedReply("no_tool_call").reason == "no_tool_call"


# ---------------------------------------------------------------- the registry


def test_provider_names() -> None:
    assert PROVIDER_NAMES == ("mock", "mock-naive", "anthropic")


@pytest.mark.parametrize(("name", "cls"), [("mock", WellBehavedMock), ("mock-naive", NaiveMock)])
def test_make_provider_builds_the_mocks(name: str, cls: type) -> None:
    budget = CallBudget(1)
    provider = make_provider(name, budget)
    assert isinstance(provider, cls)
    assert isinstance(provider, Provider)
    assert provider.name == name
    assert repr(budget) in repr(provider)


def test_make_provider_rejects_an_unknown_name() -> None:
    with pytest.raises(ProviderConfigError, match="unknown provider"):
        make_provider("gpt", CallBudget(1))


def test_make_provider_anthropic_without_a_key_is_a_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ProviderConfigError, match="ANTHROPIC_API_KEY is not set"):
        make_provider("anthropic", CallBudget(1))


@pytest.mark.parametrize("mode", ["mock", "mock-naive"])
def test_mocks_spend_one_call_each_and_then_refuse(mode: str) -> None:
    budget = CallBudget(2)
    provider = make_provider(mode, budget)
    system = golden_cases.system_prompt()
    user = golden_cases.user_prompt(golden_cases.base_alert())
    provider.complete(system, user)
    provider.complete(system, user)
    with pytest.raises(BudgetExhausted):
        provider.complete(system, user)
    assert budget.used == 2


# ---------------------------------------------------------------- lazy imports

_ISOLATED = """
import sys
import ai_security_assistant.cli
import ai_security_assistant.providers
import ai_security_assistant.providers.anthropic
import ai_security_assistant.providers.mock
import ai_security_assistant.triage
import ai_security_assistant.prompt
from ai_security_assistant.providers import CallBudget, make_provider
for name in ("mock", "mock-naive"):
    make_provider(name, CallBudget(1))
assert "anthropic" not in sys.modules, "the SDK was imported"
print("ok")
"""


def test_importing_the_package_and_building_mocks_never_imports_the_sdk() -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-c", _ISOLATED], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_selecting_anthropic_without_the_package_is_a_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder-not-a-key")
    monkeypatch.setitem(sys.modules, "anthropic", None)  # makes `import anthropic` fail
    with pytest.raises(ProviderConfigError, match="not installed"):
        make_provider("anthropic", CallBudget(1))
