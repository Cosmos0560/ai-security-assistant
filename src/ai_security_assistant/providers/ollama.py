"""The Ollama provider (D36, D37): a local open-weight model over loopback HTTP, stdlib only.

Settings (each from the environment or, through ``config.py``, from ``.env``):

* ``OLLAMA_BASE_URL``: default ``http://localhost:11434``. ``http`` or ``https`` with the host
  ``localhost``, ``127.0.0.1`` or ``[::1]``; no userinfo, no path, no query. Anything else is a
  ``ProviderConfigError`` (T13). Ollama's own ``OLLAMA_HOST`` is never read (the same reasoning as
  ``ANTHROPIC_BASE_URL``, D17).
* ``OLLAMA_MODEL``: default ``DEFAULT_MODEL``, which is the ONLY place the model name is written
  in ``src/`` or ``tests/`` (the gate enforces it).
* ``OLLAMA_TIMEOUT_SECONDS``: default 600, accepted range 1 to 3600. ``urllib`` applies it per
  socket read, and a non-streamed reply sends nothing until it is complete, so it bounds the whole
  generation on CPU (about 4 tokens/s) plus a cold model load.

The transport is locked down: an empty ``ProxyHandler`` (``HTTP(S)_PROXY`` cannot route alert data
elsewhere) and no redirects. It is also injectable (a callable taking a request and a timeout and
returning the body bytes), so tests replay recorded ``/api/chat`` bodies and never open a socket.

There are no retries: one ``complete`` is one budget unit, and a timed-out 5-minute call must not
silently become a 10-minute one. A timeout or an HTTP error is a ``ProviderError`` (triage maps it
to ``provider_error``).

The request asks for ``think: false``, ``stream: false`` and ``format`` equal to the schema of the
Anthropic tool call, so the two providers cannot drift. That only narrows what the model emits. The
guarantee stays ``triage.py``'s strict parse plus the validator: a ``<think>`` block or prose in the
content is a parse failure there, and a reply cut off at the token cap (``done_reason: "length"``)
is refused here as ``MalformedReply("truncated")``. Error messages are fixed phrases and never carry
reply text.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any, Final
from urllib.parse import urlsplit

from ai_security_assistant.providers.base import (
    CallBudget,
    MalformedReply,
    ProviderConfigError,
    ProviderError,
)
from ai_security_assistant.schema import tool_input_schema

ENV_BASE_URL: Final = "OLLAMA_BASE_URL"
ENV_MODEL: Final = "OLLAMA_MODEL"
ENV_TIMEOUT: Final = "OLLAMA_TIMEOUT_SECONDS"
DEFAULT_MODEL: Final = "qwen3:8b"
DEFAULT_BASE_URL: Final = "http://localhost:11434"
DEFAULT_TIMEOUT_SECONDS: Final = 600
TIMEOUT_RANGE: Final = (1, 3600)
HEALTH_TIMEOUT_SECONDS: Final = 10
MAX_BODY_BYTES: Final = 1024 * 1024
SEED: Final = 20260611
NUM_PREDICT: Final = 600
NUM_CTX: Final = 8192

LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})
_MODEL_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}")  # same as the Anthropic provider
_TIMEOUT_RE: Final = re.compile(r"[0-9]{1,4}")
_URL_CHARS_RE: Final = re.compile(r"[\x21-\x7e]+")

Transport = Callable[[urllib.request.Request, float], bytes]


def parse_base_url(raw: str) -> str:
    """The canonical base URL (``scheme://host[:port]``), or ``ProviderConfigError``.

    The value that was checked is the value that is used: the URL is rebuilt from the parsed
    parts, so nothing that ``urllib`` might read differently survives.
    """
    problem = (
        f"{ENV_BASE_URL} must be an http or https URL for localhost, 127.0.0.1 or [::1], "
        "with no credentials, path or query"
    )
    if _URL_CHARS_RE.fullmatch(raw) is None:
        raise ProviderConfigError(problem)
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ProviderConfigError(problem) from None
    host = (parts.hostname or "").lower()
    if (
        parts.scheme not in {"http", "https"}
        or host not in LOOPBACK_HOSTS
        or "@" in parts.netloc
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
        or "?" in raw
        or "#" in raw
    ):
        raise ProviderConfigError(problem)
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{port}" if port is not None else "")


def parse_timeout(raw: str) -> int:
    """``OLLAMA_TIMEOUT_SECONDS``: a plain whole number in ``TIMEOUT_RANGE``."""
    low, high = TIMEOUT_RANGE
    if _TIMEOUT_RE.fullmatch(raw) is not None and low <= int(raw) <= high:
        return int(raw)
    raise ProviderConfigError(f"{ENV_TIMEOUT} must be a whole number from {low} to {high}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: alert data must not follow a ``Location`` header anywhere."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # urllib then reports the 3xx as an HTTPError


def _build_opener(*extra: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    """An opener with no proxy and no redirects. ``extra`` handlers exist for tests."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), *extra)


def urllib_transport(request: urllib.request.Request, timeout: float) -> bytes:
    """The real transport. The body is read up to one byte past the cap, so oversize is visible."""
    with _build_opener().open(request, timeout=timeout) as response:
        body: bytes = response.read(MAX_BODY_BYTES + 1)
    return body


def _is_timeout(exc: BaseException) -> bool:
    return isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)


class OllamaProvider:
    """One non-streamed ``/api/chat`` request per call, against a ``CallBudget``."""

    name = "ollama"

    def __init__(
        self,
        budget: CallBudget,
        *,
        environ: Mapping[str, str] | None = None,
        transport: Transport | None = None,
    ) -> None:
        env = os.environ if environ is None else environ
        self._budget = budget
        self._base_url = parse_base_url((env.get(ENV_BASE_URL) or DEFAULT_BASE_URL).strip())
        self._model = (env.get(ENV_MODEL) or DEFAULT_MODEL).strip()
        if _MODEL_RE.fullmatch(self._model) is None:
            raise ProviderConfigError(f"{ENV_MODEL} is not a valid model name")
        raw_timeout = (env.get(ENV_TIMEOUT) or "").strip()
        self._timeout = parse_timeout(raw_timeout) if raw_timeout else DEFAULT_TIMEOUT_SECONDS
        self._transport: Transport = urllib_transport if transport is None else transport

    def __repr__(self) -> str:
        return f"OllamaProvider(model={self._model!r}, budget={self._budget!r})"

    # ------------------------------------------------------------------ start-up health check

    def preflight(self) -> None:
        """Before any alert is touched: Ollama answers, and the model is present locally.

        Two GETs, no model call, no budget unit. Never pulls anything: that is the user's job.
        """
        unreachable = f"Ollama is not reachable at {self._base_url}; is it running?"
        version = self._get_json("/api/version", unreachable)
        if not isinstance(version.get("version"), str):
            raise ProviderConfigError(f"the server at {self._base_url} did not answer like Ollama")
        tags = self._get_json(
            "/api/tags", f"could not list the models of Ollama at {self._base_url}"
        )
        models = tags.get("models")
        wanted = self._model if ":" in self._model else f"{self._model}:latest"
        names = {
            entry.get(key)
            for entry in (models if isinstance(models, list) else [])
            if isinstance(entry, dict)
            for key in ("name", "model")
        }
        if wanted not in names:
            raise ProviderConfigError(
                f"model {self._model} is not available locally; "
                f"pull it with `ollama pull {self._model}`"
            )

    def _get_json(self, path: str, failure: str) -> dict[str, Any]:
        request = urllib.request.Request(
            self._base_url + path, headers={"Accept": "application/json"}, method="GET"
        )
        try:
            body = self._transport(request, HEALTH_TIMEOUT_SECONDS)
            document = json.loads(body) if len(body) <= MAX_BODY_BYTES else None
        except (ValueError, RecursionError):
            document = None  # reachable, but not an Ollama JSON answer
        except Exception:
            raise ProviderConfigError(failure) from None
        if not isinstance(document, dict):
            raise ProviderConfigError(f"the server at {self._base_url} did not answer like Ollama")
        return document

    # ------------------------------------------------------------------ the call

    def request_body(self, system: str, user: str) -> dict[str, Any]:
        """The ``/api/chat`` request document. ``format`` is the Anthropic tool's input schema."""
        return {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "think": False,
            "format": tool_input_schema(),
            "options": {
                "temperature": 0,
                "seed": SEED,
                "num_predict": NUM_PREDICT,
                "num_ctx": NUM_CTX,
            },
        }

    def complete(self, system: str, user: str) -> str:
        self._budget.spend()  # one attempt, one unit, and there is no second attempt
        data = json.dumps(self.request_body(system, user), ensure_ascii=True, allow_nan=False)
        request = urllib.request.Request(
            self._base_url + "/api/chat",
            data=data.encode("ascii"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            body = self._transport(request, float(self._timeout))
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"ollama returned HTTP {exc.code}") from None
        except Exception as exc:
            if _is_timeout(exc):
                raise ProviderError("ollama request timed out") from None
            # The class name only: no message text, no request detail.
            raise ProviderError(f"ollama request failed ({type(exc).__name__})") from None
        return _message_content(body)


def _message_content(body: bytes) -> str:
    """``message.content`` of a finished, untruncated reply, or ``MalformedReply``."""
    if len(body) > MAX_BODY_BYTES:
        raise MalformedReply("oversize")
    try:
        document = json.loads(body)
    except (ValueError, RecursionError):  # includes bad UTF-8
        raise MalformedReply("not_json") from None
    if not isinstance(document, dict):
        raise MalformedReply("not_object")
    if document.get("done") is not True:
        raise MalformedReply("not_done")
    if document.get("done_reason") == "length":
        raise MalformedReply("truncated")
    message = document.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise MalformedReply("bad_message")
    return content
