"""Providers (D15, D17, D36). Importing this package imports no model SDK.

``make_provider`` is the only place that picks a provider by name. The Anthropic module is
imported only when it is selected, and its SDK only when a client is built. The Ollama provider
needs no SDK (stdlib HTTP); ``make_provider`` runs its start-up health check before returning it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from ai_security_assistant.providers.base import (
    BudgetExhausted,
    CallBudget,
    MalformedReply,
    Provider,
    ProviderConfigError,
    ProviderError,
)

PROVIDER_NAMES: Final = ("mock", "mock-naive", "anthropic", "ollama")


def make_provider(
    name: str, budget: CallBudget, *, settings: Mapping[str, str] | None = None
) -> Provider:
    """Build the provider called ``name``. Raises ``ProviderConfigError`` if it cannot start.

    ``settings`` (the resolved ``OLLAMA_*`` values, see ``config.py``) is read by the Ollama
    provider only; ``None`` means the process environment. The Anthropic key never travels here.
    """
    if name == "mock":
        from ai_security_assistant.providers.mock import WellBehavedMock

        return WellBehavedMock(budget)
    if name == "mock-naive":
        from ai_security_assistant.providers.mock import NaiveMock

        return NaiveMock(budget)
    if name == "anthropic":
        from ai_security_assistant.providers.anthropic import AnthropicProvider

        return AnthropicProvider(budget)
    if name == "ollama":
        from ai_security_assistant.providers.ollama import OllamaProvider

        ollama = OllamaProvider(budget, environ=settings)
        ollama.preflight()
        return ollama
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
