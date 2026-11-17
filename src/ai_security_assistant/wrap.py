"""Untrusted-data wrapping with a per-run random boundary (D8).

The untrusted fields travel to the model as ONE JSON object (``ensure_ascii``) between two
boundary lines that carry a per-run nonce::

    <<<AISA-UNTRUSTED-DATA nonce=<nonce> BEGIN>>>
    {"host":"...","message":"..."}
    <<<AISA-UNTRUSTED-DATA nonce=<nonce> END>>>

An attacker who cannot guess the nonce will try generic forged markers instead, so the data is
neutralized against the boundary FAMILY, not only the exact nonce. After NFKC and
case-insensitively:

* every ``<`` and ``>`` is written as ``\\u003c`` / ``\\u003e``, so no ``<<<`` or ``>>>`` (and no
  tag-shaped marker such as ``</untrusted>``) survives in the data;
* the first character of any text that looks like the boundary keyword (``AISA`` + ``UNTRUSTED``
  with any separators, or ``UNTRUSTED DATA/ALERT/INPUT/BLOCK``) and of any occurrence of the
  nonce itself is written as a ``\\uXXXX`` escape.

Both are JSON escapes, so ``unwrap`` (a plain ``json.loads``) restores the data exactly. The
nonce alphabet has no hex digit and no ``u``, so a nonce can never start inside a JSON escape.
"""

from __future__ import annotations

import json
import random
import re
import secrets
from collections.abc import Mapping
from typing import Final

from ai_security_assistant.sanitize import SanitizedAlert, normalize_text

BOUNDARY_TAG: Final = "AISA-UNTRUSTED-DATA"
NONCE_ALPHABET: Final = "ghijklmnopqrstvwxyz"
NONCE_LENGTH: Final = 24
MIN_NONCE_LENGTH: Final = 16

_NONCE_RE: Final = re.compile(rf"[{NONCE_ALPHABET}]{{{MIN_NONCE_LENGTH},64}}")
_FAMILY_SOURCE: Final = (
    r"a\W{0,3}i\W{0,3}s\W{0,3}a\W{0,6}u\W{0,3}n\W{0,3}t\W{0,3}r\W{0,3}u\W{0,3}s\W{0,3}t"
    r"|untrusted\W{0,6}(?:data|alert|input|block)"
)
_FAMILY_RE: Final = re.compile(_FAMILY_SOURCE, re.IGNORECASE)
# Zero-width lookahead variant: reports EVERY position where a family match could start, also
# the overlapping ones ("AISA-UNTRUSTED-DATA" holds two), which a plain ``finditer`` skips.
_FAMILY_STARTS_RE: Final = re.compile(rf"(?=(?:{_FAMILY_SOURCE}))", re.IGNORECASE)


class WrapError(ValueError):
    """A wrapped block is malformed, or a nonce is unusable."""


def new_nonce(seed: int | str | None = None) -> str:
    """A fresh nonce. ``seed=None`` uses ``secrets``; a seed (test/mock mode) is deterministic."""
    if seed is None:
        return "".join(secrets.choice(NONCE_ALPHABET) for _ in range(NONCE_LENGTH))
    rng = random.Random(f"aisa-nonce:{seed}")
    return "".join(rng.choice(NONCE_ALPHABET) for _ in range(NONCE_LENGTH))


def _check_nonce(nonce: str) -> None:
    if _NONCE_RE.fullmatch(nonce) is None:
        raise WrapError("nonce must be 16-64 characters from the nonce alphabet")


def boundaries(nonce: str) -> tuple[str, str]:
    """The BEGIN and END boundary lines for ``nonce``."""
    _check_nonce(nonce)
    return (
        f"<<<{BOUNDARY_TAG} nonce={nonce} BEGIN>>>",
        f"<<<{BOUNDARY_TAG} nonce={nonce} END>>>",
    )


def _neutralize(body: str, nonce: str) -> str:
    """Escape boundary-shaped text inside the JSON ``body``. Every change is a JSON escape."""
    body = body.replace("<", "\\u003c").replace(">", "\\u003e")
    starts = {match.start() for match in _FAMILY_STARTS_RE.finditer(body)}
    # Overlapping occurrences of the nonce count too (a nonce such as "gggg...g" repeats itself).
    nonce_starts = re.compile(f"(?=(?:{re.escape(nonce)}))", re.IGNORECASE)
    starts |= {match.start() for match in nonce_starts.finditer(body)}
    for index in sorted(starts, reverse=True):
        body = f"{body[:index]}\\u{ord(body[index]):04x}{body[index + 1 :]}"
    return body


def wrap_fields(fields: Mapping[str, str | None], nonce: str) -> str:
    """Wrap ``fields`` (already sanitized) in the nonce-tagged block."""
    begin, end = boundaries(nonce)
    payload = {
        name: None if value is None else normalize_text(value) for name, value in fields.items()
    }
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return f"{begin}\n{_neutralize(body, nonce)}\n{end}"


def wrap_alert(alert: SanitizedAlert, nonce: str) -> str:
    """Wrap the untrusted fields of a sanitized alert."""
    return wrap_fields(alert.fields, nonce)


def unwrap(wrapped: str, nonce: str) -> dict[str, str | None]:
    """Inverse of ``wrap_fields``, for tests and the validator. Strict: any deviation raises."""
    begin, end = boundaries(nonce)
    if wrapped.count(begin) != 1 or wrapped.count(end) != 1:
        raise WrapError("boundary lines are missing or repeated")
    prefix, suffix = f"{begin}\n", f"\n{end}"
    if not (wrapped.startswith(prefix) and wrapped.endswith(suffix)):
        raise WrapError("block does not start and end with its boundary lines")
    try:
        data = json.loads(wrapped[len(prefix) : -len(suffix)])
    except ValueError:
        raise WrapError("block body is not valid JSON") from None
    if not isinstance(data, dict) or not all(
        value is None or isinstance(value, str) for value in data.values()
    ):
        raise WrapError("block body is not an object of strings")
    return data
