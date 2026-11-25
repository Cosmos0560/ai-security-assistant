"""``aisa triage`` on the Ollama provider and its configuration (D37, D38), with fakes only.

The transport is replaced by a router that replays the recorded bodies in ``fixtures/ollama``; no
socket is opened and no model is called. ``.env`` handling is tested here through ``cli.main``
because that is the only place allowed to read it.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from ai_security_assistant import cli
from ai_security_assistant.cli import main
from ai_security_assistant.providers import ollama
from ai_security_assistant.providers.ollama import DEFAULT_MODEL

FIXTURES = Path(__file__).parent / "fixtures"
OLLAMA = FIXTURES / "ollama"
WAZUH = FIXTURES / "wazuh" / "alerts.jsonl"  # three alerts, in the order of chat_wazuh_1..3


@pytest.fixture(autouse=True)
def _in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)


class Router:
    """A fake Ollama: answers the health check and replays chat bodies in order."""

    def __init__(self, *chats: str, version: str = "version.json", tags: str = "tags.json") -> None:
        self.chats = [(OLLAMA / name).read_bytes() for name in chats]
        self.version = (OLLAMA / version).read_bytes()
        self.tags = (OLLAMA / tags).read_bytes()
        self.calls: list[str] = []
        self.chat_bodies: list[dict[str, Any]] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> bytes:
        self.calls.append(request.full_url)
        if request.full_url.endswith("/api/version"):
            return self.version
        if request.full_url.endswith("/api/tags"):
            return self.tags
        assert request.full_url.endswith("/api/chat")
        assert isinstance(request.data, bytes)
        self.chat_bodies.append(json.loads(request.data))
        return self.chats.pop(0)

    @property
    def chat_calls(self) -> int:
        return sum(1 for url in self.calls if url.endswith("/api/chat"))


def install(monkeypatch: pytest.MonkeyPatch, router: Any) -> Any:
    monkeypatch.setattr(ollama, "urllib_transport", router)
    return router


def run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def report() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(Path("reports/report.json").read_text(encoding="utf-8"))
    return document


def three_good() -> Router:
    return Router("chat_wazuh_1.json", "chat_wazuh_2.json", "chat_wazuh_3.json")


# ---------------------------------------------------------------- the happy path


def test_llm_provider_ollama_in_the_environment_runs_the_pipeline(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, three_good())
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    code, out, err = run(["triage", str(WAZUH)], capsys)
    assert (code, err) == (0, "")
    assert out == (
        "aisa: 3 alerts: 3 triaged, 0 needs_human_review, 0 budget_exhausted\n"
        "aisa: wrote reports/report.md\n"
        "aisa: wrote reports/report.json\n"
    )
    document = report()
    assert document["provider"] == "ollama"
    assert [a["status"] for a in document["alerts"]] == ["triaged"] * 3
    assert document["calls"] == {"used": 3, "max": 20}
    assert Path("reports/report.md").is_file()
    # The health check ran first, then exactly one chat call per alert; nothing else.
    assert [url.rsplit("/", 1)[1] for url in router.calls] == [
        "version",
        "tags",
        "chat",
        "chat",
        "chat",
    ]
    assert {url.split("/api")[0] for url in router.calls} == {"http://localhost:11434"}


def test_the_flag_runs_it_too_and_the_system_and_user_prompts_are_sent(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, three_good())
    code, _out, _err = run(["triage", "--provider", "ollama", str(WAZUH)], capsys)
    assert code == 0
    roles = [[m["role"] for m in body["messages"]] for body in router.chat_bodies]
    assert roles == [["system", "user"]] * 3
    assert {body["model"] for body in router.chat_bodies} == {DEFAULT_MODEL}
    assert {body["think"] for body in router.chat_bodies} == {False}


def test_the_budget_applies_to_ollama_like_any_provider(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, three_good())
    code, out, _err = run(
        ["triage", "--provider", "ollama", "--max-calls", "1", str(WAZUH)], capsys
    )
    assert code == 3
    assert "1 triaged, 0 needs_human_review, 2 budget_exhausted" in out
    assert router.chat_calls == 1


def test_settings_reach_the_provider(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, three_good())
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:11999")
    monkeypatch.setenv("OLLAMA_MODEL", "tiny:latest")
    router.tags = json.dumps({"models": [{"name": "tiny:latest"}]}).encode()
    code, _out, _err = run(["triage", "--provider", "ollama", str(WAZUH)], capsys)
    assert code == 0
    assert {url.split("/api")[0] for url in router.calls} == {"http://127.0.0.1:11999"}
    assert {body["model"] for body in router.chat_bodies} == {"tiny:latest"}


# ---------------------------------------------------------------- bad replies end in review


@pytest.mark.parametrize(
    ("fixture", "codes"),
    [
        # The observed qwen3 prose. Check 9 (Phase 10) also reads it: this alert has no Windows
        # codes, so every code in the prose is ungrounded, and two are paired with a wrong meaning.
        (
            "chat_hallucination_4625.json",
            [
                "schema.not_json",
                "kb.ungrounded_logon_type",
                "kb.ungrounded_status",
                "kb.contradiction_logon_type",
                "kb.contradiction_status",
            ],
        ),
        ("chat_think.json", ["schema.not_json"]),  # a <think> block before the JSON
    ],
)
def test_a_reply_that_is_not_the_json_object_goes_to_human_review(
    fixture: str,
    codes: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    install(monkeypatch, Router(fixture))
    record = WAZUH.read_text(encoding="utf-8").splitlines()[0]
    Path("one.json").write_text(record, encoding="utf-8")
    status, out, _err = run(["triage", "--provider", "ollama", "one.json"], capsys)
    assert status == 3
    entry = report()["alerts"][0]
    assert (entry["status"], entry["reason_codes"]) == ("needs_human_review", codes)
    assert entry["provider_called"] is True
    text = out + Path("reports/report.md").read_text(encoding="utf-8") + json.dumps(report())
    assert "think" not in text.lower().replace("thinking", "")
    assert "0xC000006A" not in text  # the model's prose is never printed or reported


def test_the_real_recorded_reply_goes_to_human_review_and_is_never_shown(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Valid JSON, wrong shape, and two false Windows claims: the schema check stops it, and
    check 9 (Phase 10) names the claims (ungrounded on this non-Windows alert, and contradicted)."""
    install(monkeypatch, Router("chat_real_status_logon.json"))
    Path("one.json").write_text(WAZUH.read_text(encoding="utf-8").splitlines()[0], encoding="utf-8")
    status, out, _err = run(["triage", "--provider", "ollama", "one.json"], capsys)
    assert status == 3
    entry = report()["alerts"][0]
    assert (entry["status"], entry["reason_codes"]) == (
        "needs_human_review",
        [
            "schema.schema_violation",
            "actions.missing",
            "mitre.missing",
            "kb.ungrounded_event_id",
            "kb.ungrounded_logon_type",
            "kb.ungrounded_status",
            "kb.contradiction_logon_type",
            "kb.contradiction_status",
        ],
    )
    text = out + Path("reports/report.md").read_text(encoding="utf-8") + json.dumps(report())
    assert "network logon" not in text
    assert "account does not exist" not in text


def test_a_truncated_reply_goes_to_human_review(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install(monkeypatch, Router("chat_length.json"))
    Path("one.json").write_text(WAZUH.read_text(encoding="utf-8").splitlines()[0], encoding="utf-8")
    status, _out, _err = run(["triage", "--provider", "ollama", "one.json"], capsys)
    assert status == 3
    entry = report()["alerts"][0]
    assert entry["status"] == "needs_human_review"
    assert entry["reason_codes"] == ["schema.malformed_reply"]


def test_a_timeout_during_a_call_is_provider_error_review(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class SlowAfterHealth(Router):
        def __call__(self, request: urllib.request.Request, timeout: float) -> bytes:
            if request.full_url.endswith("/api/chat"):
                raise TimeoutError("read timed out")
            return super().__call__(request, timeout)

    install(monkeypatch, SlowAfterHealth())
    status, _out, _err = run(["triage", "--provider", "ollama", str(WAZUH)], capsys)
    assert status == 3
    assert {a["status"] for a in report()["alerts"]} == {"needs_human_review"}
    assert report()["calls"]["used"] == 3  # one attempt each, no retries


# ---------------------------------------------------------------- exit 2 before any alert


def test_ollama_not_running_exits_2_with_the_clear_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def down(_request: urllib.request.Request, _timeout: float) -> bytes:
        raise ConnectionRefusedError("refused")

    install(monkeypatch, down)
    code, out, err = run(["triage", "--provider", "ollama", str(WAZUH)], capsys)
    assert code == 2
    assert out == ""
    assert err == "aisa: error: Ollama is not reachable at http://localhost:11434; is it running?\n"
    assert not Path("reports").exists()


def test_ollama_stopped_without_any_fake_is_the_same_exit_2() -> None:
    """The real transport meets the socket blocker, which makes every connection fail."""
    assert main(["triage", "--provider", "ollama", str(WAZUH)]) == 2
    assert not Path("reports").exists()


def test_a_missing_model_exits_2_and_pulls_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, Router())
    router.tags = json.dumps({"models": [{"name": "other:1b", "model": "other:1b"}]}).encode()
    code, out, err = run(["triage", "--provider", "ollama", str(WAZUH)], capsys)
    assert code == 2
    assert out == ""
    assert err == (
        f"aisa: error: model {DEFAULT_MODEL} is not available locally; "
        f"pull it with `ollama pull {DEFAULT_MODEL}`\n"
    )
    assert router.chat_calls == 0
    assert all(url.endswith(("/api/version", "/api/tags")) for url in router.calls)
    assert not Path("reports").exists()


@pytest.mark.parametrize(
    ("name", "value", "needle"),
    [
        ("OLLAMA_BASE_URL", "http://evil.test:11434", "OLLAMA_BASE_URL"),
        ("OLLAMA_BASE_URL", "http://user:pw@localhost:11434", "OLLAMA_BASE_URL"),
        ("OLLAMA_MODEL", "not a model", "OLLAMA_MODEL"),
        ("OLLAMA_TIMEOUT_SECONDS", "ten", "OLLAMA_TIMEOUT_SECONDS"),
    ],
)
def test_a_bad_setting_exits_2_before_any_request(
    name: str,
    value: str,
    needle: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    router = install(monkeypatch, Router())
    monkeypatch.setenv(name, value)
    code, out, err = run(["triage", "--provider", "ollama", str(WAZUH)], capsys)
    assert code == 2
    assert out == ""
    assert needle in err
    assert value not in err
    assert router.calls == []


# ---------------------------------------------------------------- provider resolution (D38)


def test_the_default_stays_the_offline_mock(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, Router())
    code, _out, _err = run(["triage", str(WAZUH)], capsys)
    assert code == 0
    assert report()["provider"] == "mock"
    assert router.calls == []


def test_the_flag_beats_the_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, Router())
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    code, _out, _err = run(["triage", "--provider", "mock-naive", str(WAZUH)], capsys)
    assert code == 0
    assert report()["provider"] == "mock-naive"
    assert router.calls == []


def test_an_unknown_llm_provider_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "gpt-9")
    code, out, err = run(["triage", str(WAZUH)], capsys)
    assert (code, out) == (2, "")
    assert err == "aisa: error: LLM_PROVIDER is not a known provider\n"
    assert "gpt-9" not in err


# ---------------------------------------------------------------- .env (D38)


@pytest.fixture
def dotenv(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make ``aisa triage`` read ``.env`` from the (temporary) current directory."""
    monkeypatch.setattr(cli, "DOTENV_PATH", Path(".env"))
    return Path(".env")


def test_dotenv_selects_the_provider_and_configures_it(
    dotenv: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, three_good())
    router.tags = json.dumps({"models": [{"name": "tiny:latest"}]}).encode()
    dotenv.write_text(
        "# local model\nLLM_PROVIDER=ollama\nOLLAMA_MODEL='tiny:latest'\n"
        'OLLAMA_BASE_URL="http://127.0.0.1:11999"\nOLLAMA_TIMEOUT_SECONDS=30\n',
        encoding="utf-8",
    )
    code, _out, err = run(["triage", str(WAZUH)], capsys)
    assert (code, err) == (0, "")
    assert report()["provider"] == "ollama"
    assert {url.split("/api")[0] for url in router.calls} == {"http://127.0.0.1:11999"}
    assert {body["model"] for body in router.chat_bodies} == {"tiny:latest"}


def test_a_real_environment_variable_beats_the_file(
    dotenv: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, Router())
    dotenv.write_text("LLM_PROVIDER=ollama\n", encoding="utf-8")
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    code, _out, _err = run(["triage", str(WAZUH)], capsys)
    assert code == 0
    assert report()["provider"] == "mock"
    assert router.calls == []


def test_the_default_dotenv_is_never_read_under_the_test_suite(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The autouse fixture points cli.DOTENV_PATH away from a developer's own file."""
    assert cli.DOTENV_PATH.name != ".env"
    Path(".env").write_text("LLM_PROVIDER=ollama\nANTHROPIC_API_KEY=x\n", encoding="utf-8")
    router = install(monkeypatch, Router())
    code, _out, _err = run(["triage", str(WAZUH)], capsys)
    assert code == 0
    assert report()["provider"] == "mock"
    assert router.calls == []


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("ANTHROPIC_API_KEY=sk-test\n", "the API key is read only from the environment"),
        ("MY_TOKEN=abc\n", "the API key is read only from the environment"),
        ("db_password=abc\n", "the API key is read only from the environment"),
        ("OLLAMA_HOST=http://evil.test\n", "unknown key OLLAMA_HOST"),
        ("HTTPS_PROXY=http://evil.test\n", "unknown key HTTPS_PROXY"),
        ("export LLM_PROVIDER=ollama\n", "line 1 is not a KEY=VALUE line"),
        ("LLM_PROVIDER\n", "line 1 is not a KEY=VALUE line"),
    ],
)
def test_a_bad_dotenv_refuses_to_start_without_echoing_a_value(
    text: str,
    needle: str,
    dotenv: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    router = install(monkeypatch, Router())
    dotenv.write_text(text, encoding="utf-8")
    code, out, err = run(["triage", str(WAZUH)], capsys)
    assert (code, out) == (2, "")
    assert needle in err
    for value in ("sk-test", "abc", "evil.test"):
        assert value not in err
    assert router.calls == []
    assert not Path("reports").exists()


def test_a_dotenv_that_is_a_directory_is_refused(
    dotenv: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dotenv.mkdir()
    code, _out, err = run(["triage", str(WAZUH)], capsys)
    assert (code, err) == (2, "aisa: error: cannot read .env\n")


def test_eval_ignores_llm_provider_and_dotenv(
    dotenv: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A stray variable or file must never send the eval (or the gate's README check) to a model."""
    router = install(monkeypatch, Router())
    dotenv.write_text("LLM_PROVIDER=ollama\nANTHROPIC_API_KEY=x\n", encoding="utf-8")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    code, out, err = run(["eval"], capsys)
    assert (code, err) == (0, "")
    assert json.loads(out)["providers"]["ablation"] == "mock-naive"
    assert router.calls == []


def test_an_ollama_eval_without_a_results_file_calls_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("CI", raising=False)
    assert main(["eval", "--provider", "ollama"]) == 2
    assert "needs --out" in capsys.readouterr().err


def test_dry_run_reads_no_configuration_and_calls_nothing(
    dotenv: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    router = install(monkeypatch, Router())
    dotenv.write_text("ANTHROPIC_API_KEY=x\n", encoding="utf-8")
    code, out, _err = run(["triage", "--dry-run", "--provider", "ollama", str(WAZUH)], capsys)
    assert code == 0
    assert "detector" in json.loads(out)[0]
    assert router.calls == []
