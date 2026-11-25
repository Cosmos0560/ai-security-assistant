"""One provider call and a STRICT parse of its reply (D11).

The whole reply must be a single JSON object that matches ``schema.TriageOutput``. There is no
code-fence stripping, no "find the JSON in the prose" and no repair: a reply that is not exactly
that is a failure, and a hijacked model cannot smuggle free text past the validator through a
lenient parser.

Every outcome is a ``TriageResult`` value; nothing here raises for a bad reply or a failed call.
Phase 5 maps any status other than ``ok`` to ``needs_human_review``. The result carries fixed
reason codes only, never the model's text in a message, and the raw text is hidden from ``repr``.

The IOC, MITRE-allowlist, canary and length checks of D12 are Phase 5; this module only fixes the
shape.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, NoReturn

from pydantic import ValidationError

from ai_security_assistant.providers.base import (
    BudgetExhausted,
    ContextBudgetExceeded,
    MalformedReply,
    Provider,
    ProviderError,
)
from ai_security_assistant.schema import TriageOutput

MAX_REPLY_CHARS: Final = 16_384

# The fixed reason codes of a parse failure.
REASON_TOO_LONG: Final = "too_long"
REASON_EMPTY: Final = "empty"
REASON_NOT_JSON: Final = "not_json"
REASON_DUPLICATE_KEY: Final = "duplicate_key"
REASON_NOT_OBJECT: Final = "not_object"
REASON_SCHEMA: Final = "schema_violation"


class TriageStatus(StrEnum):
    OK = "ok"
    PARSE_FAILURE = "parse_failure"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PROVIDER_ERROR = "provider_error"
    REFUSED_CONTEXT_BUDGET = "refused_context_budget"  # no request was made


@dataclass(frozen=True)
class TriageResult:
    """The outcome of one triage call. ``output`` is set exactly when ``status`` is ``ok``."""

    status: TriageStatus
    output: TriageOutput | None = None
    reason: str | None = None
    # The reply as the provider returned it (None if there was none). Untrusted; kept for the
    # Phase 5 canary check and never shown by repr.
    raw_text: str | None = field(default=None, repr=False)


class _StrictJsonError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise _StrictJsonError(REASON_DUPLICATE_KEY)
    return dict(pairs)


def _no_constants(_name: str) -> NoReturn:
    raise _StrictJsonError(REASON_NOT_JSON)  # NaN, Infinity, -Infinity are not JSON


def parse_triage(text: str) -> tuple[TriageOutput | None, str | None]:
    """``(output, None)`` for a valid reply, or ``(None, reason code)``. Never raises."""
    if not isinstance(text, str):
        return None, REASON_NOT_JSON
    if len(text) > MAX_REPLY_CHARS:
        return None, REASON_TOO_LONG
    if not text.strip():
        return None, REASON_EMPTY
    try:
        document = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except _StrictJsonError as exc:
        return None, exc.reason
    except (ValueError, RecursionError):
        return None, REASON_NOT_JSON
    if not isinstance(document, dict):
        return None, REASON_NOT_OBJECT
    try:
        return TriageOutput.model_validate_json(text, strict=True), None
    except ValidationError:
        return None, REASON_SCHEMA


def triage_alert(provider: Provider, system: str, user: str) -> TriageResult:
    """One provider call, one strict parse. The result is a value, whatever happens."""
    try:
        text = provider.complete(system, user)
    except BudgetExhausted:
        return TriageResult(TriageStatus.BUDGET_EXHAUSTED)
    except MalformedReply as exc:
        return TriageResult(TriageStatus.PARSE_FAILURE, reason=exc.reason)
    except ContextBudgetExceeded:
        return TriageResult(TriageStatus.REFUSED_CONTEXT_BUDGET)
    except ProviderError:
        return TriageResult(TriageStatus.PROVIDER_ERROR)
    output, reason = parse_triage(text)
    if output is None:
        return TriageResult(TriageStatus.PARSE_FAILURE, reason=reason, raw_text=text)
    return TriageResult(TriageStatus.OK, output=output, raw_text=text)
