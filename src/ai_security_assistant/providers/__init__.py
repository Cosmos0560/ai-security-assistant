"""Providers (D15, D17). Importing this package imports no model SDK.

``make_provider`` is the only place that picks a provider by name. The Anthropic module is
imported only when it is selected, and its SDK only when a client is built.
"""

from __future__ import annotations

from typing import Final

from ai_security_assistant.providers.base import (
    BudgetExhausted,
    CallBudget,
    MalformedReply,
    Provider,
    ProviderConfigError,
    ProviderError,
)

PROVIDER_NAMES: Final = ("mock", "mock-naive", "anthropic")


def make_provider(name: str, budget: CallBudget) -> Provider:
    """Build the provider called ``name``. Raises ``ProviderConfigError`` if it cannot start."""
    if name == "mock":
        from ai_security_assistant.providers.mock import WellBehavedMock

        return WellBehavedMock(budget)
    if name == "mock-naive":
        from ai_security_assistant.providers.mock import NaiveMock

        return NaiveMock(budget)
    if name == "anthropic":
        from ai_security_assistant.providers.anthropic import AnthropicProvider

        return AnthropicProvider(budget)
    raise ProviderConfigError("unknown provider")


__all__ = [
    "PROVIDER_NAMES",
    "BudgetExhausted",
    "CallBudget",
    "MalformedReply",
    "Provider",
    "ProviderConfigError",
    "ProviderError",
    "make_provider",
]
