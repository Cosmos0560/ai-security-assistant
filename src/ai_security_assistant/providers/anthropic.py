"""The optional Anthropic provider (D17). The SDK is the extra ``[anthropic]``, imported lazily.

Settings, all from the environment, never from a file or a flag:

* ``ANTHROPIC_API_KEY``: the only source of the key. It is passed to the SDK client constructor
  and kept nowhere else: not on the provider, not in a message, not in ``repr``.
* ``AISA_ANTHROPIC_MODEL``: the model, default ``claude-haiku-5-5``.
* ``AISA_ANTHROPIC_BASE_URL``: an explicit endpoint, ``https`` only. The SDK's own
  ``ANTHROPIC_BASE_URL`` is IGNORED on purpose: ``base_url`` is always passed explicitly (default
  ``https://api.anthropic.com``). An inherited variable could otherwise send the alert data and the
  key to a host the user never chose.

Cost guard: a ``max_tokens`` cap, a per-request timeout, and a bounded retry loop of our own. The
SDK's internal retries are switched off (``max_retries=0``) because they would spend calls the
``CallBudget`` never sees; every attempt here, retries included, spends one unit.

No sampling parameter is sent. Claude Haiku 5.5 rejects any non-default ``temperature``, ``top_p``
or ``top_k`` with a 400 (and API version 2026-10-21 rejects them on every model), so replies are
not deterministic; the forced tool call and the strict parse constrain the output instead.

Structured output uses a forced tool call whose ``input_schema`` is the triage schema. Claude Haiku
5.5 accepts a forced ``tool_choice`` and then skips thinking, so the reply is the tool call alone
and ``MAX_TOKENS`` covers it. Some current models (Claude Opus 5.5, Claude Sonnet 5.5, Claude
Fable 5.1 and 5.2) reject a forced ``tool_choice`` with a 400; ``AISA_ANTHROPIC_MODEL`` must name a
model that accepts it. The tool input comes back as raw JSON text for ``triage.py``'s strict parse;
a reply with no tool call, more than one, or a truncated one is a ``MalformedReply`` (a parse
failure), never a guess.
"""

from __future__ import annotations

import importlib
import json
import os
import re
from collections.abc import Callable, Mapping
from typing import Any, Final

from ai_security_assistant.providers.base import (
    CallBudget,
    MalformedReply,
    ProviderConfigError,
    ProviderError,
)
from ai_security_assistant.schema import tool_input_schema

ENV_API_KEY: Final = "ANTHROPIC_API_KEY"
ENV_MODEL: Final = "AISA_ANTHROPIC_MODEL"
ENV_BASE_URL: Final = "AISA_ANTHROPIC_BASE_URL"
DEFAULT_MODEL: Final = "claude-haiku-5-5"
DEFAULT_BASE_URL: Final = "https://api.anthropic.com"
MAX_TOKENS: Final = 600
REQUEST_TIMEOUT_SECONDS: Final = 30.0
SDK_MAX_RETRIES: Final = 0
MAX_ATTEMPTS: Final = 2  # the call plus one retry, every attempt counted against the budget
TOOL_NAME: Final = "submit_triage"
TOOL_DESCRIPTION: Final = "Submit the triage of the alert. This is the only way to answer."

_MODEL_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")
_RETRYABLE_CLASSES: Final = frozenset(
    {"APIConnectionError", "APITimeoutError", "RateLimitError", "InternalServerError"}
)
_RETRYABLE_STATUS: Final = frozenset({408, 409, 429})

ClientFactory = Callable[..., Any]


def _sdk_client(**kwargs: Any) -> Any:
    """The real SDK client. The only place the SDK is imported."""
    try:
        sdk = importlib.import_module("anthropic")
    except ImportError:
        raise ProviderConfigError(
            "the anthropic package is not installed (install the 'anthropic' extra)"
        ) from None
    return sdk.Anthropic(**kwargs)


def _retryable(exc: BaseException) -> bool:
    if any(cls.__name__ in _RETRYABLE_CLASSES for cls in type(exc).__mro__):
        return True
    status = getattr(exc, "status_code", None)
    return isinstance(status, int) and (status in _RETRYABLE_STATUS or status >= 500)


class AnthropicProvider:
    """One forced-tool-call request per attempt, against a ``CallBudget``."""

    name = "anthropic"

    def __init__(
        self,
        budget: CallBudget,
        *,
        environ: Mapping[str, str] | None = None,
        client: Any = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        env = os.environ if environ is None else environ
        self._budget = budget
        self._model = (env.get(ENV_MODEL) or DEFAULT_MODEL).strip()
        if _MODEL_RE.fullmatch(self._model) is None:
            raise ProviderConfigError(f"{ENV_MODEL} is not a valid model name")
        base_url = (env.get(ENV_BASE_URL) or DEFAULT_BASE_URL).strip()
        if not base_url.startswith("https://"):
            raise ProviderConfigError(f"{ENV_BASE_URL} must start with https://")
        if client is None:
            key = (env.get(ENV_API_KEY) or "").strip()
            if not key:
                raise ProviderConfigError(f"{ENV_API_KEY} is not set")
            factory = _sdk_client if client_factory is None else client_factory
            # The key goes to the SDK constructor and nowhere else. base_url is explicit, so an
            # inherited ANTHROPIC_BASE_URL is never consulted.
            try:
                client = factory(
                    api_key=key,
                    base_url=base_url,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    max_retries=SDK_MAX_RETRIES,
                )
            except ProviderConfigError:
                raise
            except Exception as exc:
                # The class name only: a constructor error must never echo the key.
                raise ProviderConfigError(
                    f"could not create the anthropic client ({type(exc).__name__})"
                ) from None
        self._client = client

    @property
    def model(self) -> str:
        return self._model

    def __repr__(self) -> str:
        return f"AnthropicProvider(model={self._model!r}, budget={self._budget!r})"

    def complete(self, system: str, user: str) -> str:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._budget.spend()
            try:
                response = self._client.messages.create(
                    model=self._model,
                    max_tokens=MAX_TOKENS,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                    tools=[
                        {
                            "name": TOOL_NAME,
                            "description": TOOL_DESCRIPTION,
                            "input_schema": tool_input_schema(),
                        }
                    ],
                    tool_choice={"type": "tool", "name": TOOL_NAME},
                )
            except Exception as exc:
                if attempt < MAX_ATTEMPTS and _retryable(exc):
                    continue
                # The class name only: no message text, no request detail, never the key.
                raise ProviderError(f"anthropic request failed ({type(exc).__name__})") from None
            return _tool_input_json(response)
        raise ProviderError("anthropic request failed")  # pragma: no cover (loop always returns)


def _tool_input_json(response: Any) -> str:
    """The forced tool's input as JSON text, or ``MalformedReply``."""
    if getattr(response, "stop_reason", None) == "max_tokens":
        raise MalformedReply("truncated")
    content = getattr(response, "content", None)
    blocks = (
        [b for b in content if getattr(b, "type", None) == "tool_use"]
        if isinstance(content, (list, tuple))
        else []
    )
    if not blocks:
        raise MalformedReply("no_tool_call")
    if len(blocks) > 1:
        raise MalformedReply("extra_tool_call")
    block = blocks[0]
    if getattr(block, "name", None) != TOOL_NAME:
        raise MalformedReply("wrong_tool")
    tool_input = getattr(block, "input", None)
    if not isinstance(tool_input, dict):
        raise MalformedReply("bad_tool_input")
    try:
        return json.dumps(tool_input, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        raise MalformedReply("bad_tool_input") from None
