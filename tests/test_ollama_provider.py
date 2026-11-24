"""The Ollama provider (D36, D37) against a FAKE transport that replays recorded bodies.

No socket is opened (the autouse blocker stays in force) and nothing real is called. The one test
that exercises the real opener swaps in a fake HTTP handler, so even that stays off the network.
"""

from __future__ import annotations

import email.message
import http.client
import io
import json
import urllib.error
import urllib.request
import urllib.response
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ai_security_assistant.providers import ollama
from ai_security_assistant.providers.base import (
    BudgetExhausted,
    CallBudget,
    MalformedReply,
    Provider,
    ProviderConfigError,
    ProviderError,
)
from ai_security_assistant.providers.ollama import (
    DEFAULT_MODEL,
    MAX_BODY_BYTES,
    NUM_CTX,
    NUM_PREDICT,
    SEED,
    OllamaProvider,
    parse_base_url,
    parse_timeout,
)
from ai_security_assistant.schema import tool_input_schema
from ai_security_assistant.triage import TriageStatus, triage_alert

FIXTURES = Path(__file__).parent / "fixtures" / "ollama"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class FakeTransport:
    """Replays queued outcomes (bytes, or an exception to raise) and records every request."""

    def __init__(self, *outcomes: bytes | BaseException) -> None:
        self.outcomes = list(outcomes)
        self.requests: list[tuple[urllib.request.Request, float]] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> bytes:
        self.requests.append((request, timeout))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def body(self, index: int = 0) -> dict[str, Any]:
        data = self.requests[index][0].data
        assert isinstance(data, bytes)
        document: dict[str, Any] = json.loads(data)
        return document


def make(
    *outcomes: bytes | BaseException,
    env: dict[str, str] | None = None,
    budget: CallBudget | None = None,
) -> tuple[OllamaProvider, FakeTransport, CallBudget]:
    transport = FakeTransport(*outcomes)
    budget = budget or CallBudget(10)
    return OllamaProvider(budget, environ=env or {}, transport=transport), transport, budget


# ---------------------------------------------------------------- the URL policy (T13)


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("http://localhost:11434", "http://localhost:11434"),
        ("http://localhost:11434/", "http://localhost:11434"),
        ("http://127.0.0.1:11434", "http://127.0.0.1:11434"),
        ("http://[::1]:11434", "http://[::1]:11434"),
        ("https://localhost", "https://localhost"),
        ("HTTP://LocalHost:9", "http://localhost:9"),
    ],
)
def test_loopback_urls_are_accepted_and_canonicalised(raw: str, canonical: str) -> None:
    assert parse_base_url(raw) == canonical


@pytest.mark.parametrize(
    "raw",
    [
        "http://example.com:11434",  # remote host
        "http://192.0.2.5:11434",  # not loopback
        "http://0.0.0.0:11434",
        "http://127.0.0.2:11434",
        "http://localhost.example.com:11434",
        "http://localhost" + "@" + "evil.test:11434",  # userinfo that looks like the host
        "http://user:pass@localhost:11434",
        "http://evil.test@localhost:11434",
        "http://localhost:11434/api",  # a path
        "http://localhost:11434/v1/",
        "http://localhost:11434?x=1",  # a query
        "http://localhost:11434?",
        "http://localhost:11434#frag",
        "ftp://localhost:11434",
        "file://localhost/etc/passwd",
        "localhost:11434",
        "//localhost:11434",
        "",
        "http://",
        "http://localhost:notaport",
        "http://localhost:99999999",
        "http://localhost:11434 ",  # whitespace
        "http://local\nhost:11434",  # control characters urllib would silently drop
        "http://localhost\\@evil.test:11434",
        "http://[::1:11434",
        "http://löcalhost:11434",
    ],
)
def test_everything_else_is_refused(raw: str) -> None:
    with pytest.raises(ProviderConfigError) as exc:
        parse_base_url(raw)
    assert "localhost" in str(exc.value)
    assert raw.strip() == "" or raw not in str(exc.value)  # the value is never echoed


def test_a_bad_base_url_stops_the_provider_before_any_request() -> None:
    transport = FakeTransport()
    with pytest.raises(ProviderConfigError, match="OLLAMA_BASE_URL"):
        OllamaProvider(
            CallBudget(1), environ={"OLLAMA_BASE_URL": "http://evil.test"}, transport=transport
        )
    assert transport.requests == []


def test_ollama_host_is_ignored() -> None:
    """Ollama's own OLLAMA_HOST must not redirect anything (the same rule as ANTHROPIC_BASE_URL)."""
    p, transport, _budget = make(
        fixture("chat_wazuh_1.json"), env={"OLLAMA_HOST": "http://evil.test:1"}
    )
    p.complete("s", "u")
    assert transport.requests[0][0].full_url == "http://localhost:11434/api/chat"


def test_the_process_environment_is_used_when_no_settings_are_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:2")
    monkeypatch.setenv("OLLAMA_HOST", "http://evil.test:1")
    transport = FakeTransport(fixture("chat_wazuh_1.json"))
    OllamaProvider(CallBudget(1), transport=transport).complete("s", "u")
    assert transport.requests[0][0].full_url == "http://127.0.0.1:2/api/chat"


# ---------------------------------------------------------------- model and timeout settings


def test_defaults() -> None:
    p, transport, _budget = make(fixture("chat_wazuh_1.json"))
    p.complete("s", "u")
    request, timeout = transport.requests[0]
    assert transport.body()["model"] == DEFAULT_MODEL
    assert timeout == 600.0
    assert request.full_url == "http://localhost:11434/api/chat"
    assert repr(p).startswith("OllamaProvider(model=")


def test_model_and_timeout_come_from_the_settings() -> None:
    env = {"OLLAMA_MODEL": " llama3.2:3b ", "OLLAMA_TIMEOUT_SECONDS": "45"}
    p, transport, _budget = make(fixture("chat_wazuh_1.json"), env=env)
    p.complete("s", "u")
    assert transport.body()["model"] == "llama3.2:3b"
    assert transport.requests[0][1] == 45.0


def test_the_model_name_regex_matches_the_anthropic_providers() -> None:
    from ai_security_assistant.providers import anthropic

    assert ollama._MODEL_RE.pattern == anthropic._MODEL_RE.pattern


@pytest.mark.parametrize("model", ["bad model", "-lead", "a" * 101, "x;rm", "mödel"])
def test_a_bad_model_name_is_refused(model: str) -> None:
    with pytest.raises(ProviderConfigError, match="OLLAMA_MODEL"):
        OllamaProvider(CallBudget(1), environ={"OLLAMA_MODEL": model}, transport=FakeTransport())


@pytest.mark.parametrize("value", ["1", "600", "3600"])
def test_timeout_inside_the_range(value: str) -> None:
    assert parse_timeout(value) == int(value)


@pytest.mark.parametrize("value", ["0", "3601", "-5", "1.5", "ten", "0600x", "99999", "+5"])
def test_timeout_outside_the_range_or_not_a_whole_number(value: str) -> None:
    with pytest.raises(ProviderConfigError, match="OLLAMA_TIMEOUT_SECONDS"):
        parse_timeout(value)
    with pytest.raises(ProviderConfigError, match="OLLAMA_TIMEOUT_SECONDS"):
        OllamaProvider(
            CallBudget(1), environ={"OLLAMA_TIMEOUT_SECONDS": value}, transport=FakeTransport()
        )


def test_the_timeout_setting_is_stripped_but_the_parser_is_strict() -> None:
    with pytest.raises(ProviderConfigError):
        parse_timeout(" 5")
    p, transport, _budget = make(
        fixture("chat_wazuh_1.json"), env={"OLLAMA_TIMEOUT_SECONDS": " 5 "}
    )
    p.complete("s", "u")
    assert transport.requests[0][1] == 5.0


# ---------------------------------------------------------------- the request (D36)


def test_the_request_asks_for_structured_unstreamed_deterministic_output() -> None:
    p, transport, budget = make(fixture("chat_wazuh_1.json"))
    p.complete("the system prompt", "the user prompt")
    (request, _timeout) = transport.requests[0]
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    body = transport.body()
    assert body["think"] is False
    assert body["stream"] is False
    assert body["format"] == tool_input_schema()
    assert body["options"] == {
        "temperature": 0,
        "seed": SEED,
        "num_predict": NUM_PREDICT,
        "num_ctx": NUM_CTX,
    }
    assert body["messages"] == [
        {"role": "system", "content": "the system prompt"},
        {"role": "user", "content": "the user prompt"},
    ]
    assert set(body) == {"model", "messages", "stream", "think", "format", "options"}
    assert budget.used == 1


def test_the_request_body_is_ascii_json_whatever_the_prompt_holds() -> None:
    p, transport, _budget = make(fixture("chat_wazuh_1.json"))
    p.complete("sys ‮", "user да \U0001f600")
    data = transport.requests[0][0].data
    assert isinstance(data, bytes)
    data.decode("ascii")
    assert transport.body()["messages"][1]["content"] == "user да \U0001f600"


# ---------------------------------------------------------------- budget, errors, no retry


def test_the_budget_is_spent_once_per_call_and_never_retried() -> None:
    p, transport, budget = make(OSError("down"))
    with pytest.raises(ProviderError):
        p.complete("s", "u")
    assert budget.used == 1
    assert len(transport.requests) == 1  # no second attempt, whatever failed


def test_an_empty_budget_makes_no_request() -> None:
    p, transport, _budget = make(budget=CallBudget(0))
    with pytest.raises(BudgetExhausted):
        p.complete("s", "u")
    assert transport.requests == []


def test_a_timeout_is_a_provider_error_with_a_fixed_message() -> None:
    p, _transport, budget = make(TimeoutError("timed out after reading secret-ish text"))
    with pytest.raises(ProviderError) as exc:
        p.complete("s", "u")
    assert str(exc.value) == "ollama request timed out"
    assert budget.used == 1


def test_a_url_error_wrapping_a_timeout_is_a_timeout_too() -> None:
    p, _transport, _budget = make(urllib.error.URLError(TimeoutError("slow")))
    with pytest.raises(ProviderError, match="timed out"):
        p.complete("s", "u")


@pytest.mark.parametrize("code", [400, 404, 500, 503])
def test_an_http_error_is_a_provider_error_without_the_body(code: int) -> None:
    error = urllib.error.HTTPError(
        "http://localhost:11434/api/chat",
        code,
        "reason text",
        email.message.Message(),
        io.BytesIO(b'{"error": "model exploded"}'),
    )
    p, _transport, _budget = make(error)
    with pytest.raises(ProviderError) as exc:
        p.complete("s", "u")
    assert str(exc.value) == f"ollama returned HTTP {code}"
    assert "exploded" not in str(exc.value)


def test_other_failures_name_only_the_exception_class() -> None:
    p, _transport, _budget = make(ConnectionResetError("peer said something private"))
    with pytest.raises(ProviderError) as exc:
        p.complete("s", "u")
    assert str(exc.value) == "ollama request failed (ConnectionResetError)"


def test_a_provider_error_reaches_triage_as_provider_error() -> None:
    p, _transport, _budget = make(TimeoutError())
    assert triage_alert(p, "s", "u").status is TriageStatus.PROVIDER_ERROR


# ---------------------------------------------------------------- the reply


def test_the_content_comes_back_as_the_raw_text_for_the_strict_parse() -> None:
    p, _transport, _budget = make(fixture("chat_wazuh_1.json"))
    result = triage_alert(p, "s", "u")
    assert result.status is TriageStatus.OK
    assert result.output is not None
    assert result.output.mitre_technique == "T1110"
    assert json.loads(result.raw_text or "")["severity"] == "low"


def test_done_reason_length_is_a_truncated_reply() -> None:
    p, _transport, _budget = make(fixture("chat_length.json"))
    with pytest.raises(MalformedReply) as exc:
        p.complete("s", "u")
    assert exc.value.reason == "truncated"
    p, _transport, _budget = make(fixture("chat_length.json"))
    result = triage_alert(p, "s", "u")
    assert (result.status, result.reason) == (TriageStatus.PARSE_FAILURE, "truncated")


def test_a_think_block_in_the_content_is_a_parse_failure() -> None:
    p, _transport, _budget = make(fixture("chat_think.json"))
    result = triage_alert(p, "s", "u")
    assert (result.status, result.reason) == (TriageStatus.PARSE_FAILURE, "not_json")
    assert "<think>" in (result.raw_text or "")


def test_prose_in_the_content_is_a_parse_failure() -> None:
    p, _transport, _budget = make(fixture("chat_hallucination_4625.json"))
    result = triage_alert(p, "s", "u")
    assert (result.status, result.reason) == (TriageStatus.PARSE_FAILURE, "not_json")


def reply(**overrides: Any) -> bytes:
    document: dict[str, Any] = {
        "model": DEFAULT_MODEL,
        "message": {"role": "assistant", "content": "{}"},
        "done": True,
        "done_reason": "stop",
    }
    document.update(overrides)
    return json.dumps(document).encode("ascii")


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"not json at all", "not_json"),
        (b"", "not_json"),
        (b"\xff\xfe\xfa", "not_json"),  # not UTF-8
        (b"[" * 100_000, "not_json"),  # nesting deep enough to raise RecursionError
        (b"[1, 2]", "not_object"),
        (b'"text"', "not_object"),
        (reply(done=False), "not_done"),
        (reply(done="true"), "not_done"),
        (b'{"error": "boom"}', "not_done"),
        (reply(message=None), "bad_message"),
        (reply(message="text"), "bad_message"),
        (reply(message={"role": "assistant"}), "bad_message"),
        (reply(message={"content": 5}), "bad_message"),
        (reply(message={"content": None}), "bad_message"),
        (b"x" * (MAX_BODY_BYTES + 1), "oversize"),
        (reply(padding="x" * MAX_BODY_BYTES), "oversize"),
    ],
)
def test_a_malformed_body_is_a_fixed_reason_code(body: bytes, reason: str) -> None:
    p, _transport, budget = make(body)
    with pytest.raises(MalformedReply) as exc:
        p.complete("s", "u")
    assert exc.value.reason == reason
    assert budget.used == 1  # the call was made and paid for


def test_a_body_exactly_at_the_cap_is_still_read() -> None:
    base = reply(padding="")
    padded = reply(padding="x" * (MAX_BODY_BYTES - len(base)))
    assert len(padded) == MAX_BODY_BYTES
    p, _transport, _budget = make(padded)
    assert p.complete("s", "u") == "{}"


def test_a_thinking_field_beside_the_content_is_ignored() -> None:
    body = reply(message={"role": "assistant", "content": "{}", "thinking": "private chain"})
    p, _transport, _budget = make(body)
    assert p.complete("s", "u") == "{}"


def test_done_reason_may_be_absent() -> None:
    document = json.loads(reply())
    del document["done_reason"]
    p, _transport, _budget = make(json.dumps(document).encode("ascii"))
    assert p.complete("s", "u") == "{}"


def test_the_provider_satisfies_the_protocol() -> None:
    p, _transport, _budget = make()
    assert isinstance(p, Provider)
    assert p.name == "ollama"


# ---------------------------------------------------------------- the health check (D37)


def test_preflight_passes_when_ollama_runs_and_the_model_is_present() -> None:
    p, transport, budget = make(fixture("version.json"), fixture("tags.json"))
    p.preflight()
    assert [r.full_url for r, _t in transport.requests] == [
        "http://localhost:11434/api/version",
        "http://localhost:11434/api/tags",
    ]
    assert {r.get_method() for r, _t in transport.requests} == {"GET"}
    assert {t for _r, t in transport.requests} == {float(ollama.HEALTH_TIMEOUT_SECONDS)}
    assert all(r.data is None for r, _t in transport.requests)
    assert budget.used == 0  # no model call, no budget unit


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.URLError(ConnectionRefusedError("refused")),
        ConnectionRefusedError("refused"),
        TimeoutError("slow"),
        OSError("unreachable"),
    ],
)
def test_ollama_not_running_is_a_config_error_with_the_clear_message(failure: Exception) -> None:
    p, transport, _budget = make(failure)
    with pytest.raises(ProviderConfigError) as exc:
        p.preflight()
    assert str(exc.value) == "Ollama is not reachable at http://localhost:11434; is it running?"
    assert len(transport.requests) == 1  # it never got as far as listing models


def test_the_message_names_the_configured_address() -> None:
    p, _transport, _budget = make(OSError(), env={"OLLAMA_BASE_URL": "http://127.0.0.1:2/"})
    with pytest.raises(ProviderConfigError) as exc:
        p.preflight()
    assert str(exc.value) == "Ollama is not reachable at http://127.0.0.1:2; is it running?"


def test_a_missing_model_says_how_to_pull_it_and_never_pulls() -> None:
    p, transport, _budget = make(
        fixture("version.json"),
        json.dumps({"models": [{"name": "llama3.2:3b", "model": "llama3.2:3b"}]}).encode(),
    )
    with pytest.raises(ProviderConfigError) as exc:
        p.preflight()
    assert str(exc.value) == (
        f"model {DEFAULT_MODEL} is not available locally; "
        f"pull it with `ollama pull {DEFAULT_MODEL}`"
    )
    assert {r.get_method() for r, _t in transport.requests} == {"GET"}
    assert not any("pull" in r.full_url for r, _t in transport.requests)


def test_a_model_without_a_tag_means_latest() -> None:
    tags = json.dumps({"models": [{"name": "tiny:latest", "model": "tiny:latest"}]}).encode()
    p, _transport, _budget = make(fixture("version.json"), tags, env={"OLLAMA_MODEL": "tiny"})
    p.preflight()


def test_no_models_listed_is_a_missing_model() -> None:
    for tags in (b'{"models": []}', b"{}", b'{"models": "x"}', b'{"models": [1, null, {}]}'):
        p, _transport, _budget = make(fixture("version.json"), tags)
        with pytest.raises(ProviderConfigError, match="not available locally"):
            p.preflight()


def test_listing_the_models_can_fail_too() -> None:
    p, _transport, _budget = make(fixture("version.json"), OSError("reset"))
    with pytest.raises(ProviderConfigError, match="could not list the models"):
        p.preflight()


@pytest.mark.parametrize(
    "body",
    [b"<html>not ollama</html>", b"[]", b'{"nope": 1}', b'{"version": 3}', b"", b"x" * 2_000_000],
)
def test_something_else_on_the_port_is_not_ollama(body: bytes) -> None:
    p, _transport, _budget = make(body)
    with pytest.raises(ProviderConfigError, match="did not answer like Ollama"):
        p.preflight()


# ---------------------------------------------------------------- the real transport, no socket


class FakeHttpHandler(urllib.request.HTTPHandler):
    """Stands in for the real HTTP handler so ``urllib`` never reaches a socket."""

    def __init__(self, status: int = 200, headers: dict[str, str] | None = None) -> None:
        super().__init__()
        self.status = status
        self.headers = headers or {}
        self.seen: list[urllib.request.Request] = []

    def http_open(self, req: urllib.request.Request) -> Any:
        self.seen.append(req)
        message = http.client.HTTPMessage()
        for name, value in self.headers.items():
            message[name] = value
        response = urllib.response.addinfourl(io.BytesIO(b'{"ok": true}'), message, req.full_url)
        response.code = self.status
        response.msg = "fake"
        return response


REAL_BUILD_OPENER = ollama._build_opener  # captured before any test patches it


def opener_with(handler: FakeHttpHandler) -> urllib.request.OpenerDirector:
    return REAL_BUILD_OPENER(handler)


def test_the_opener_ignores_proxy_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://evil.test:3128")
    handler = FakeHttpHandler()
    opener = opener_with(handler)
    # The empty ProxyHandler replaces urllib's default one, which reads the variables, and
    # registers nothing itself: no proxy handler is left in the opener.
    assert not [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert urllib.request.getproxies()["http"] == "http://evil.test:3128"  # the trap is armed
    opener.open(urllib.request.Request("http://localhost:11434/api/version")).read()
    (seen,) = handler.seen
    assert seen.host == "localhost:11434"  # not rewritten to the proxy
    assert seen.full_url == "http://localhost:11434/api/version"


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_refused(status: int) -> None:
    handler = FakeHttpHandler(status, {"Location": "http://evil.test/steal"})
    opener = opener_with(handler)
    request = urllib.request.Request("http://localhost:11434/api/chat", data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        opener.open(request)
    assert exc.value.code == status
    assert len(handler.seen) == 1  # the Location was never followed


def test_a_refused_redirect_reaches_the_caller_as_a_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = FakeHttpHandler(302, {"Location": "http://evil.test/steal"})
    monkeypatch.setattr(ollama, "_build_opener", lambda *extra: opener_with(handler))
    p = OllamaProvider(CallBudget(1), environ={})  # the real transport, the fake handler
    with pytest.raises(ProviderError, match="HTTP 302"):
        p.complete("s", "u")
    assert [r.full_url for r in handler.seen] == ["http://localhost:11434/api/chat"]


def test_the_real_transport_returns_at_most_one_byte_past_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.asked: list[int] = []

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def read(self, amount: int) -> bytes:
            self.asked.append(amount)
            return b"y" * amount

    response = Response()

    class Opener:
        def open(self, request: urllib.request.Request, timeout: float) -> Response:
            assert timeout == 7.5
            return response

    monkeypatch.setattr(ollama, "_build_opener", lambda *extra: Opener())
    body = ollama.urllib_transport(urllib.request.Request("http://localhost:11434/x"), 7.5)
    assert len(body) == MAX_BODY_BYTES + 1
    assert response.asked == [MAX_BODY_BYTES + 1]


def test_the_default_transport_is_looked_up_when_the_provider_is_built(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake: Callable[[urllib.request.Request, float], bytes] = FakeTransport(
        fixture("chat_wazuh_1.json")
    )
    monkeypatch.setattr(ollama, "urllib_transport", fake)
    assert OllamaProvider(CallBudget(1), environ={}).complete("s", "u").startswith("{")
