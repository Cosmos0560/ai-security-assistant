"""``config.py``: the ``.env`` reader and provider resolution (D38). Pure functions, no network."""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_security_assistant.config import (
    ALLOWED_KEYS,
    MAX_FILE_BYTES,
    MAX_VALUE_CHARS,
    ConfigError,
    load_settings,
    parse_dotenv,
    read_dotenv,
    resolve_provider,
)
from ai_security_assistant.providers import PROVIDER_NAMES

# Built at runtime: the fake credential is not shaped like any real key.
FAKE_SECRET = "test-key-" + "q7" * 12


def test_the_allowed_keys_are_exactly_the_four() -> None:
    assert ALLOWED_KEYS == (
        "LLM_PROVIDER",
        "OLLAMA_BASE_URL",
        "OLLAMA_MODEL",
        "OLLAMA_TIMEOUT_SECONDS",
    )


# ---------------------------------------------------------------- the file format


def test_pairs_comments_and_blank_lines() -> None:
    text = (
        "# a comment\n\nLLM_PROVIDER=ollama\n   OLLAMA_MODEL = tiny:latest  \n"
        "  # indented comment\r\nOLLAMA_TIMEOUT_SECONDS=30\r\n"
    )
    assert parse_dotenv(text) == {
        "LLM_PROVIDER": "ollama",
        "OLLAMA_MODEL": "tiny:latest",
        "OLLAMA_TIMEOUT_SECONDS": "30",
    }


def test_an_empty_text_is_an_empty_configuration() -> None:
    assert parse_dotenv("") == {}
    assert parse_dotenv("\n# only a comment\n") == {}


@pytest.mark.parametrize(
    ("raw", "value"),
    [
        ('"quoted"', "quoted"),
        ("'single'", "single"),
        ("\"mismatched'", "\"mismatched'"),  # only a matching pair is stripped
        ("'", "'"),
        ('""', ""),
        ("a=b", "a=b"),  # the first = splits; the rest is the value
        ("a # not a comment", "a # not a comment"),  # no trailing comments
        ("$HOME", "$HOME"),  # no interpolation
        ("a" + chr(92) + "nb", "a" + chr(92) + "nb"),  # no escapes
        ("", ""),
    ],
)
def test_values_are_literal(raw: str, value: str) -> None:
    assert parse_dotenv(f"LLM_PROVIDER={raw}\n") == {"LLM_PROVIDER": value}


@pytest.mark.parametrize(
    "text",
    [
        "export LLM_PROVIDER=ollama",
        "LLM_PROVIDER",
        "=value",
        "1BAD=x",
        "BAD KEY=x",
        "LLM-PROVIDER=x",
        "LLM_PROVIDER: ollama",
        "A" * 65 + "=x",
        "ŁLM=x",
    ],
)
def test_a_line_that_is_not_key_value_is_refused(text: str) -> None:
    with pytest.raises(ConfigError, match="line 1 is not a KEY=VALUE line"):
        parse_dotenv(text + "\n")


def test_the_line_number_is_reported() -> None:
    with pytest.raises(ConfigError, match="line 3"):
        parse_dotenv("# one\nLLM_PROVIDER=mock\nnonsense\n")


@pytest.mark.parametrize("key", ["FOO", "OLLAMA_HOST", "HTTP_PROXY", "llm_provider", "PATH"])
def test_an_unknown_key_is_an_error_that_names_the_key_only(key: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_dotenv(f"{key}={FAKE_SECRET}\n")
    assert str(exc.value) == f".env line 1: unknown key {key}"
    assert FAKE_SECRET not in str(exc.value)


@pytest.mark.parametrize(
    "key",
    [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "client_secret",
        "DB_PASSWORD",
        "KEY",
        "OLLAMA_API_KEY",  # near an allowed name, still refused as a secret
        "MONKEY",  # contains KEY: refused rather than guessed at
    ],
)
def test_a_secret_like_key_refuses_to_start(key: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_dotenv(f"{key}={FAKE_SECRET}\n")
    message = str(exc.value)
    assert message == f".env must not contain {key}: the API key is read only from the environment"
    assert FAKE_SECRET not in message


def test_the_first_offending_line_is_the_one_reported() -> None:
    with pytest.raises(ConfigError, match="API key is read only from the environment"):
        parse_dotenv("LLM_PROVIDER=mock\nANTHROPIC_API_KEY=x\nUNKNOWN=1\n")
    with pytest.raises(ConfigError, match="unknown key UNKNOWN"):
        parse_dotenv("UNKNOWN=1\nANTHROPIC_API_KEY=x\n")


def test_a_key_set_twice_is_refused() -> None:
    with pytest.raises(ConfigError, match="line 2: LLM_PROVIDER is set twice"):
        parse_dotenv("LLM_PROVIDER=mock\nLLM_PROVIDER=ollama\n")


@pytest.mark.parametrize("value", ["café", "tab\there", "bell\x07", "x" * (MAX_VALUE_CHARS + 1)])
def test_an_unusable_value_is_refused_without_echoing_it(value: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_dotenv(f"OLLAMA_MODEL={value}\n")
    assert str(exc.value) == ".env line 1: the value of OLLAMA_MODEL is not usable"


def test_a_value_at_the_length_limit_is_kept() -> None:
    value = "x" * MAX_VALUE_CHARS
    assert parse_dotenv(f"OLLAMA_MODEL={value}\n") == {"OLLAMA_MODEL": value}


# ---------------------------------------------------------------- the file on disk


def test_an_absent_file_is_an_empty_configuration(tmp_path: Path) -> None:
    assert read_dotenv(tmp_path / ".env") == {}


def test_a_file_is_read_with_a_bom_and_crlf(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_bytes(b"\xef\xbb\xbfLLM_PROVIDER=ollama\r\n")
    assert read_dotenv(path) == {"LLM_PROVIDER": "ollama"}


def test_a_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / ".env").mkdir()
    with pytest.raises(ConfigError, match="cannot read .env"):
        read_dotenv(tmp_path / ".env")


def test_a_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_bytes(b"LLM_PROVIDER=\xff\xfe\n")
    with pytest.raises(ConfigError, match="cannot read .env"):
        read_dotenv(path)


def test_an_oversize_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_bytes(b"#" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ConfigError, match="larger than"):
        read_dotenv(path)
    path.write_bytes(b"#" * MAX_FILE_BYTES)
    assert read_dotenv(path) == {}


def test_the_default_path_is_the_current_directory_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("OLLAMA_MODEL=here\n", encoding="utf-8")
    assert load_settings({}) == {"OLLAMA_MODEL": "here"}
    other = tmp_path / "sub"
    other.mkdir()
    monkeypatch.chdir(other)  # a parent directory's file is never looked at
    assert load_settings({}) == {}


# ---------------------------------------------------------------- merging and precedence


def test_the_environment_wins_over_the_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("LLM_PROVIDER=ollama\nOLLAMA_MODEL=from-file\n", encoding="utf-8")
    settings = load_settings({"LLM_PROVIDER": "mock"}, path)
    assert settings == {"LLM_PROVIDER": "mock", "OLLAMA_MODEL": "from-file"}


def test_an_empty_variable_counts_as_unset(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("LLM_PROVIDER=ollama\nOLLAMA_MODEL=\n", encoding="utf-8")
    settings = load_settings({"LLM_PROVIDER": "  ", "OLLAMA_MODEL": ""}, path)
    assert settings == {"LLM_PROVIDER": "ollama"}


def test_only_the_allowed_keys_are_taken_from_the_environment(tmp_path: Path) -> None:
    environ = {
        "LLM_PROVIDER": "mock",
        "OLLAMA_HOST": "http://evil.test",
        "HTTP_PROXY": "http://evil.test",
        "ANTHROPIC_API_KEY": FAKE_SECRET,
        "PATH": "x",
    }
    settings = load_settings(environ, tmp_path / ".env")
    assert settings == {"LLM_PROVIDER": "mock"}
    assert FAKE_SECRET not in repr(settings)


def test_the_process_environment_is_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OLLAMA_MODEL", "from-env")
    assert load_settings(dotenv_path=tmp_path / ".env") == {"OLLAMA_MODEL": "from-env"}


def test_a_bad_file_fails_even_when_the_environment_would_win(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("ANTHROPIC_API_KEY=x\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings({"LLM_PROVIDER": "mock"}, path)


# ---------------------------------------------------------------- provider resolution


def test_the_flag_then_the_setting_then_mock() -> None:
    assert resolve_provider("anthropic", {"LLM_PROVIDER": "ollama"}) == "anthropic"
    assert resolve_provider(None, {"LLM_PROVIDER": "ollama"}) == "ollama"
    assert resolve_provider(None, {}) == "mock"
    assert resolve_provider("", {}) == "mock"


@pytest.mark.parametrize("name", PROVIDER_NAMES)
def test_every_registered_provider_resolves(name: str) -> None:
    assert resolve_provider(None, {"LLM_PROVIDER": name}) == name


@pytest.mark.parametrize("name", ["gpt", "OLLAMA", "ollama ", "mock;x", "../mock"])
def test_an_unknown_provider_name_is_refused(name: str) -> None:
    with pytest.raises(ConfigError) as exc:
        resolve_provider(None, {"LLM_PROVIDER": name})
    assert str(exc.value) == "LLM_PROVIDER is not a known provider"
