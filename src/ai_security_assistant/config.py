"""The ``.env`` reader and provider resolution (D38). Stdlib only.

Only ``cli.main`` calls this, and only for ``aisa triage``; ``aisa eval`` ignores ``LLM_PROVIDER``
and ``.env`` so a stray variable or file can never send the eval (or the gate's README drift check)
to a model. Library code and tests never read ``.env``.

The file format is deliberately tiny:

* ``KEY=VALUE`` lines, blank lines and ``#`` comment lines; nothing else. No ``export``, no
  interpolation, no escapes, no multi-line values, no trailing comments (write a comment on its
  own line). One matching pair of quotes around a value is stripped.
* Only the keys in ``ALLOWED_KEYS``. An unknown key is an error that names the key, never the value.
* A key that looks like a secret (contains ``KEY``, ``TOKEN``, ``SECRET`` or ``PASSWORD``), such as
  ``ANTHROPIC_API_KEY``, refuses to start: the API key is read only from the environment.
* A real environment variable wins over the file. An empty value counts as unset.

Error messages never carry a value.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from ai_security_assistant.providers import PROVIDER_NAMES
from ai_security_assistant.providers.ollama import ENV_BASE_URL, ENV_MODEL, ENV_TIMEOUT

ENV_PROVIDER: Final = "LLM_PROVIDER"
ALLOWED_KEYS: Final = (ENV_PROVIDER, ENV_BASE_URL, ENV_MODEL, ENV_TIMEOUT)
DEFAULT_PROVIDER: Final = "mock"
DOTENV_NAME: Final = ".env"
MAX_FILE_BYTES: Final = 16 * 1024
MAX_VALUE_CHARS: Final = 512
SECRET_WORDS: Final = ("KEY", "TOKEN", "SECRET", "PASSWORD")

_KEY_RE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_VALUE_RE: Final = re.compile(r"[\x20-\x7e]*")


class ConfigError(Exception):
    """The configuration cannot be used. The message is safe to print (no values)."""


def parse_dotenv(text: str) -> dict[str, str]:
    """The ``KEY=VALUE`` pairs of a ``.env`` text, or ``ConfigError``."""
    values: dict[str, str] = {}
    for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, value = stripped.partition("=")
        key = key.strip()
        if not separator or _KEY_RE.fullmatch(key) is None:
            raise ConfigError(f"{DOTENV_NAME} line {number} is not a KEY=VALUE line")
        if any(word in key.upper() for word in SECRET_WORDS):
            raise ConfigError(
                f"{DOTENV_NAME} must not contain {key}: "
                "the API key is read only from the environment"
            )
        if key not in ALLOWED_KEYS:
            raise ConfigError(f"{DOTENV_NAME} line {number}: unknown key {key}")
        if key in values:
            raise ConfigError(f"{DOTENV_NAME} line {number}: {key} is set twice")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if len(value) > MAX_VALUE_CHARS or _VALUE_RE.fullmatch(value) is None:
            raise ConfigError(f"{DOTENV_NAME} line {number}: the value of {key} is not usable")
        values[key] = value
    return values


def read_dotenv(path: Path) -> dict[str, str]:
    """The pairs of the file at ``path``; an absent file is an empty configuration."""
    if not path.exists():
        return {}
    problem = f"cannot read {DOTENV_NAME}"
    try:
        if not path.is_file():
            raise ConfigError(problem)
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise ConfigError(f"{DOTENV_NAME} is larger than {MAX_FILE_BYTES} bytes")
        text = data.decode("utf-8-sig")
    except (OSError, UnicodeDecodeError):
        raise ConfigError(problem) from None
    return parse_dotenv(text)


def load_settings(
    environ: Mapping[str, str] | None = None, dotenv_path: Path = Path(DOTENV_NAME)
) -> dict[str, str]:
    """The four allowed settings that are set, the environment winning over the file.

    ``dotenv_path`` is relative to the current directory by default. No other key of ``environ``
    is looked at, and none is ever copied: ``OLLAMA_HOST`` and every proxy or key variable stay out.
    """
    env = os.environ if environ is None else environ
    file_values = read_dotenv(dotenv_path)
    settings: dict[str, str] = {}
    for key in ALLOWED_KEYS:
        value = (env.get(key) or "").strip() or file_values.get(key, "")
        if value:
            settings[key] = value
    return settings


def resolve_provider(cli_value: str | None, settings: Mapping[str, str]) -> str:
    """``--provider`` if given, else ``LLM_PROVIDER``, else ``mock``; always a known name."""
    name = cli_value or settings.get(ENV_PROVIDER) or DEFAULT_PROVIDER
    if name not in PROVIDER_NAMES:
        raise ConfigError(f"{ENV_PROVIDER} is not a known provider")
    return name
