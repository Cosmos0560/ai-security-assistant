"""The provider abstraction (D15) and the shared call budget (D17).

A provider turns ``(system prompt, user prompt)`` into the model's raw reply text. It never parses
or judges that text: ``triage.py`` parses it strictly and Phase 5 validates it.

Every provider spends one unit of the run's ``CallBudget`` per attempt, retries included, and
signals trouble with a ``ProviderError`` subclass instead of returning partial text:

* ``BudgetExhausted``: no call left; triage maps it to the ``budget_exhausted`` result;
* ``MalformedReply``: the reply cannot even be turned into text (for example a missing tool call);
  triage maps it to a parse failure;
* ``ProviderConfigError``: the provider cannot start (missing key, missing package); the CLI maps
  it to exit 2 before any alert is touched;
* any other ``ProviderError``: the call failed; triage maps it to ``provider_error``.

Error messages never carry the API key or any reply text.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class ProviderError(Exception):
    """A provider call failed. The message is a fixed, safe phrase."""


class ProviderConfigError(ProviderError):
    """The provider cannot be set up (missing key, missing package, bad setting)."""


class BudgetExhausted(ProviderError):
    """The run's call budget is spent."""


class MalformedReply(ProviderError):
    """The provider got a reply that cannot be handed over as text. ``reason`` is a fixed code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class CallBudget:
    """A cap on provider calls, shared by every call of one run."""

    def __init__(self, max_calls: int) -> None:
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 0:
            raise ValueError("max_calls must be a non-negative integer")
        self._max = max_calls
        self._used = 0

    @property
    def max_calls(self) -> int:
        return self._max

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return self._max - self._used

    def spend(self) -> None:
        """Count one call, or raise ``BudgetExhausted`` without counting."""
        if self._used >= self._max:
            raise BudgetExhausted("call budget exhausted")
        self._used += 1

    def __repr__(self) -> str:
        return f"CallBudget(used={self._used}, max_calls={self._max})"


@runtime_checkable
class Provider(Protocol):
    """One model behind one call."""

    name: str

    def complete(self, system: str, user: str) -> str:
        """The model's raw reply text. Spends the budget; may raise ``ProviderError``."""
        ...
