"""The Anthropic provider, against a STUB client only. No SDK, no HTTP layer, no socket."""

from __future__ import annotations

import json
import sys
import traceback
from types import SimpleNamespace
from typing import Any

import pytest

from ai_security_assistant.providers.anthropic import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    MAX_ATTEMPTS,
    MAX_TOKENS,
    REQUEST_TIMEOUT_SECONDS,
    SDK_MAX_RETRIES,
    TOOL_NAME,
    AnthropicProvider,
)
from ai_security_assistant.providers.base import (
    BudgetExhausted,
    CallBudget,
    MalformedReply,
    ProviderConfigError,
    ProviderError,
)
from ai_security_assistant.schema import tool_input_schema
from ai_security_assistant.triage import TriageStatus, triage_alert

# Built at runtime, and not shaped like any real key.
KEY = "test-key-" + "q7" * 12
GOOD: dict[str, Any] = {
    "severity": "medium",
    "mitre_technique": "T1190",
    "summary": "A web probe.",
    "recommended_actions": ["investigate"],
    "confidence": 0.6,
}


def tool_reply(tool_input: Any = GOOD, *, name: str = TOOL_NAME, stop: str = "tool_use") -> Any:
    block = SimpleNamespace(type="tool_use", name=name, input=tool_input)
    return SimpleNamespace(content=[block], stop_reason=stop)


class Messages:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class Client:
    def __init__(self, *outcomes: Any) -> None:
        self.messages = Messages(list(outcomes))


class APIConnectionError(Exception):  # the SDK's class name, matched by name
    pass


class APITimeoutError(APIConnectionError):
    pass


class StatusError(Exception):
    def __init__(self, status_code: int, message: str = "boom") -> None:
        super().__init__(message)
        self.status_code = status_code


def provider(
    *outcomes: Any, budget: CallBudget | None = None, env: dict[str, str] | None = None
) -> tuple[AnthropicProvider, Client, CallBudget]:
    client = Client(*outcomes)
    budget = budget or CallBudget(10)
    return AnthropicProvider(budget, environ=env or {}, client=client), client, budget


# ---------------------------------------------------------------- the request


def test_the_request_is_a_forced_tool_call_with_every_cost_guard() -> None:
    p, client, budget = provider(tool_reply())
    p.complete("the system prompt", "the user prompt")
    (call,) = client.messages.calls
    assert call["model"] == DEFAULT_MODEL == "claude-haiku-5-5"
    assert call["max_tokens"] == MAX_TOKENS
    assert call["temperature"] == 0
    assert call["timeout"] == REQUEST_TIMEOUT_SECONDS
    assert call["system"] == "the system prompt"
    assert call["messages"] == [{"role": "user", "content": "the user prompt"}]
    assert call["tool_choice"] == {"type": "tool", "name": TOOL_NAME}
    (tool,) = call["tools"]
    assert tool["name"] == TOOL_NAME
    assert tool["input_schema"] == tool_input_schema()
    assert budget.used == 1


def test_the_tool_input_comes_back_as_raw_json_for_the_strict_parse() -> None:
    p, _client, _budget = provider(tool_reply())
    result = triage_alert(p, "s", "u")
    assert result.status is TriageStatus.OK
    assert result.output is not None
    assert json.loads(result.raw_text or "") == GOOD


def test_text_blocks_next_to_the_one_tool_call_are_ignored() -> None:
    reply = tool_reply()
    reply.content.insert(0, SimpleNamespace(type="text", text="Here you go"))
    p, _c, _b = provider(reply)
    assert json.loads(p.complete("s", "u")) == GOOD


def test_non_ascii_in_the_tool_input_is_escaped() -> None:
    p, _c, _b = provider(tool_reply({**GOOD, "summary": "café ‮"}))
    text = p.complete("s", "u")
    assert text.isascii()
    assert json.loads(text)["summary"] == "café ‮"


# ---------------------------------------------------------------- settings


def test_model_comes_from_the_environment() -> None:
    p, client, _b = provider(tool_reply(), env={"AISA_ANTHROPIC_MODEL": "claude-test-1"})
    p.complete("s", "u")
    assert client.messages.calls[0]["model"] == "claude-test-1"


@pytest.mark.parametrize("model", ["bad model", "x" * 101, "m;rm", "-lead", "a/b"])
def test_a_bad_model_name_is_refused(model: str) -> None:
    with pytest.raises(ProviderConfigError, match="AISA_ANTHROPIC_MODEL"):
        AnthropicProvider(CallBudget(1), environ={"AISA_ANTHROPIC_MODEL": model}, client=Client())


@pytest.mark.parametrize("url", ["http://api.example.test", "ftp://x", "api.example.test"])
def test_only_an_https_base_url_is_accepted(url: str) -> None:
    env = {"AISA_ANTHROPIC_BASE_URL": url, "ANTHROPIC_API_KEY": KEY}
    with pytest.raises(ProviderConfigError, match="https://"):
        AnthropicProvider(CallBudget(1), environ=env)


class Factory:
    """Records what the SDK client would be built with."""

    def __init__(self) -> None:
        self.kwargs: dict[str, Any] = {}

    def __call__(self, **kwargs: Any) -> Client:
        self.kwargs = kwargs
        return Client(tool_reply())


def test_the_client_gets_an_explicit_base_url_timeout_and_no_sdk_retries() -> None:
    factory = Factory()
    AnthropicProvider(CallBudget(1), environ={"ANTHROPIC_API_KEY": KEY}, client_factory=factory)
    assert factory.kwargs == {
        "api_key": KEY,
        "base_url": DEFAULT_BASE_URL,
        "timeout": REQUEST_TIMEOUT_SECONDS,
        "max_retries": SDK_MAX_RETRIES,
    }
    assert SDK_MAX_RETRIES == 0
    assert DEFAULT_BASE_URL == "https://api.anthropic.com"


def test_an_inherited_anthropic_base_url_is_ignored() -> None:
    factory = Factory()
    env = {"ANTHROPIC_API_KEY": KEY, "ANTHROPIC_BASE_URL": "https://elsewhere.example.test"}
    AnthropicProvider(CallBudget(1), environ=env, client_factory=factory)
    assert factory.kwargs["base_url"] == DEFAULT_BASE_URL


def test_the_aisa_base_url_wins_when_set() -> None:
    factory = Factory()
    env = {
        "ANTHROPIC_API_KEY": KEY,
        "ANTHROPIC_BASE_URL": "https://elsewhere.example.test",
        "AISA_ANTHROPIC_BASE_URL": "https://gateway.example.test",
    }
    AnthropicProvider(CallBudget(1), environ=env, client_factory=factory)
    assert factory.kwargs["base_url"] == "https://gateway.example.test"


def test_the_real_sdk_path_passes_base_url_explicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default factory, with a fake `anthropic` module: ANTHROPIC_BASE_URL is in os.environ
    but the constructor still receives the default endpoint."""
    seen: dict[str, Any] = {}

    class FakeAnthropic:
        def __init__(self, **kwargs: Any) -> None:
            seen.update(kwargs)
            self.messages = Messages([tool_reply()])

    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=FakeAnthropic))
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://elsewhere.example.test")
    monkeypatch.delenv("AISA_ANTHROPIC_BASE_URL", raising=False)
    p = AnthropicProvider(CallBudget(1))
    assert seen["base_url"] == DEFAULT_BASE_URL
    assert seen["max_retries"] == 0
    assert json.loads(p.complete("s", "u")) == GOOD


def test_a_missing_or_blank_key_is_a_clear_config_error() -> None:
    for env in ({}, {"ANTHROPIC_API_KEY": ""}, {"ANTHROPIC_API_KEY": "   "}):
        with pytest.raises(ProviderConfigError, match="ANTHROPIC_API_KEY is not set"):
            AnthropicProvider(CallBudget(1), environ=env)


def test_an_injected_client_needs_no_key() -> None:
    AnthropicProvider(CallBudget(1), environ={}, client=Client())


def test_a_failing_factory_never_echoes_its_message() -> None:
    def factory(**kwargs: Any) -> Any:
        raise RuntimeError(f"cannot use {kwargs['api_key']}")

    with pytest.raises(ProviderConfigError) as info:
        AnthropicProvider(CallBudget(1), environ={"ANTHROPIC_API_KEY": KEY}, client_factory=factory)
    assert KEY not in str(info.value)
    assert "RuntimeError" in str(info.value)
    assert KEY not in "".join(traceback.format_exception(info.value))


def test_a_config_error_from_the_factory_passes_through() -> None:
    def factory(**kwargs: Any) -> Any:
        raise ProviderConfigError("the anthropic package is not installed")

    with pytest.raises(ProviderConfigError, match="not installed"):
        AnthropicProvider(CallBudget(1), environ={"ANTHROPIC_API_KEY": KEY}, client_factory=factory)


# ---------------------------------------------------------------- the budget and retries


def test_the_budget_is_spent_per_call_and_exhaustion_is_a_result() -> None:
    p, client, budget = provider(tool_reply(), tool_reply(), budget=CallBudget(1))
    assert triage_alert(p, "s", "u").status is TriageStatus.OK
    second = triage_alert(p, "s", "u")
    assert second.status is TriageStatus.BUDGET_EXHAUSTED
    assert budget.used == 1
    assert len(client.messages.calls) == 1  # the exhausted call never reached the client


def test_an_exhausted_budget_raises_before_any_request() -> None:
    p, client, _b = provider(budget=CallBudget(0))
    with pytest.raises(BudgetExhausted):
        p.complete("s", "u")
    assert client.messages.calls == []


def test_a_retry_counts_against_the_budget() -> None:
    p, client, budget = provider(APIConnectionError("net"), tool_reply())
    assert json.loads(p.complete("s", "u")) == GOOD
    assert len(client.messages.calls) == 2
    assert budget.used == 2


def test_a_timeout_error_is_retried_once() -> None:
    p, client, budget = provider(APITimeoutError("t"), tool_reply())
    p.complete("s", "u")
    assert (len(client.messages.calls), budget.used) == (2, 2)


@pytest.mark.parametrize("status", [408, 409, 429, 500, 503, 529])
def test_retryable_status_codes_are_retried(status: int) -> None:
    p, client, budget = provider(StatusError(status), tool_reply())
    p.complete("s", "u")
    assert (len(client.messages.calls), budget.used) == (2, 2)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_other_status_codes_are_not_retried(status: int) -> None:
    p, client, budget = provider(StatusError(status), tool_reply())
    with pytest.raises(ProviderError, match="StatusError"):
        p.complete("s", "u")
    assert (len(client.messages.calls), budget.used) == (1, 1)


def test_retries_are_bounded_and_every_attempt_is_counted() -> None:
    p, client, budget = provider(*[APIConnectionError("net")] * 5)
    with pytest.raises(ProviderError, match="APIConnectionError"):
        p.complete("s", "u")
    assert len(client.messages.calls) == MAX_ATTEMPTS == 2
    assert budget.used == MAX_ATTEMPTS


def test_a_retry_that_cannot_be_afforded_is_budget_exhausted() -> None:
    p, client, budget = provider(APIConnectionError("net"), tool_reply(), budget=CallBudget(1))
    result = triage_alert(p, "s", "u")
    assert result.status is TriageStatus.BUDGET_EXHAUSTED
    assert (len(client.messages.calls), budget.used) == (1, 1)


def test_a_failed_call_is_a_provider_error_result() -> None:
    p, _c, _b = provider(StatusError(401))
    assert triage_alert(p, "s", "u").status is TriageStatus.PROVIDER_ERROR


# ---------------------------------------------------------------- the key never leaks


def test_the_key_never_appears_in_an_error_string_repr_or_traceback() -> None:
    env = {"ANTHROPIC_API_KEY": KEY}
    client = Client(RuntimeError(f"401 for key {KEY}"))
    p = AnthropicProvider(CallBudget(3), environ=env, client_factory=lambda **kw: client)
    with pytest.raises(ProviderError) as info:
        p.complete("s", "u")
    shown = [
        str(info.value),
        repr(info.value),
        "".join(traceback.format_exception(info.value)),
        repr(p),
        str(p),
        repr(vars(p)),
    ]
    assert all(KEY not in text for text in shown)
    assert "RuntimeError" in str(info.value)


def test_the_key_is_not_kept_on_the_provider() -> None:
    p = AnthropicProvider(
        CallBudget(1), environ={"ANTHROPIC_API_KEY": KEY}, client_factory=lambda **kw: Client()
    )
    assert KEY not in repr(vars(p))
    assert KEY not in repr(p)


def test_a_result_never_carries_the_key() -> None:
    env = {"ANTHROPIC_API_KEY": KEY}
    client = Client(RuntimeError(KEY))
    p = AnthropicProvider(CallBudget(3), environ=env, client_factory=lambda **kw: client)
    assert KEY not in repr(triage_alert(p, "s", "u"))


# ---------------------------------------------------------------- malformed replies


def malformed(reply: Any) -> MalformedReply:
    p, _c, _b = provider(reply)
    with pytest.raises(MalformedReply) as info:
        p.complete("s", "u")
    return info.value


def test_a_missing_tool_call_is_a_parse_failure() -> None:
    for content in ([], [SimpleNamespace(type="text", text="{}")], None, "not a list"):
        reply = SimpleNamespace(content=content, stop_reason="end_turn")
        assert malformed(reply).reason == "no_tool_call"
    p, _c, _b = provider(SimpleNamespace(content=[], stop_reason="end_turn"))
    result = triage_alert(p, "s", "u")
    assert (result.status, result.reason) == (TriageStatus.PARSE_FAILURE, "no_tool_call")


def test_an_extra_tool_call_is_a_parse_failure() -> None:
    reply = tool_reply()
    reply.content.append(SimpleNamespace(type="tool_use", name=TOOL_NAME, input=GOOD))
    assert malformed(reply).reason == "extra_tool_call"
    p, _c, _b = provider(reply)
    result = triage_alert(p, "s", "u")
    assert (result.status, result.reason) == (TriageStatus.PARSE_FAILURE, "extra_tool_call")


def test_the_wrong_tool_name_is_a_parse_failure() -> None:
    assert malformed(tool_reply(name="other_tool")).reason == "wrong_tool"


@pytest.mark.parametrize("bad", [None, "text", [GOOD], 5])
def test_a_tool_input_that_is_not_an_object_is_a_parse_failure(bad: Any) -> None:
    assert malformed(tool_reply(bad)).reason == "bad_tool_input"


def test_a_tool_input_json_cannot_hold_nan() -> None:
    assert malformed(tool_reply({**GOOD, "confidence": float("nan")})).reason == "bad_tool_input"


def test_a_truncated_reply_is_a_parse_failure() -> None:
    assert malformed(tool_reply(stop="max_tokens")).reason == "truncated"


def test_a_schema_violating_tool_input_fails_the_strict_parse() -> None:
    p, _c, _b = provider(tool_reply({**GOOD, "recommended_actions": ["wipe_disk"]}))
    result = triage_alert(p, "s", "u")
    assert (result.status, result.reason) == (TriageStatus.PARSE_FAILURE, "schema_violation")
    p, _c, _b = provider(tool_reply({**GOOD, "extra": 1}))
    assert triage_alert(p, "s", "u").status is TriageStatus.PARSE_FAILURE


def test_repr_names_the_model_and_the_budget_only() -> None:
    p, _c, _b = provider(env={"AISA_ANTHROPIC_MODEL": "claude-test-1"})
    assert (
        repr(p)
        == "AnthropicProvider(model='claude-test-1', budget=CallBudget(used=0, max_calls=10))"
    )
