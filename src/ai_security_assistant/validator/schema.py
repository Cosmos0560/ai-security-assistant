"""Check 1 (schema) and the two readings of a reply that every other check works on (D11, D12).

The STRICT reading is ``triage.parse_triage``: the whole reply must be one JSON object that
matches ``schema.TriageOutput``. It decides whether anything can be accepted at all. It lives in
the validator layer: ``triage_alert`` keeps the raw reply (``TriageResult.raw_text``) even when
the strict parse fails, so a pipeline run with the validator OFF (the D22 ablation) can
still read the reply with ``read_permissive`` and report what a fooled model produced.

The PERMISSIVE reading (``read_permissive``) never fails. It accepts any JSON, duplicate keys
and off-schema values included, and falls back to the raw text when the reply is not JSON. The
checks 2 to 8 run on it, so a reply that already failed the strict parse still gets a precise
reason (an off-allowlist action fails the enum parse, and check 2 says so). Nothing from the
permissive reading is ever accepted: an accepted result always carries the strict output.

``Context`` is what every check receives. Checks return rule ids from fixed sets, never text
taken from the reply or the alert.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from ai_security_assistant.kb import PatternFact
from ai_security_assistant.models import Alert
from ai_security_assistant.schema import TriageOutput
from ai_security_assistant.triage import (
    REASON_DUPLICATE_KEY,
    REASON_EMPTY,
    REASON_NOT_JSON,
    REASON_NOT_OBJECT,
    REASON_SCHEMA,
    REASON_TOO_LONG,
    TriageResult,
    TriageStatus,
    parse_triage,
)

# Only this much of a reply is read; the length check (6) reports anything longer.
MAX_ANALYSIS_CHARS: Final = 65_536
# The permissive walk stops after this many strings; the length check reports the overflow.
MAX_WALK_ITEMS: Final = 4_096

RULE_NO_REPLY: Final = "no_reply"
RULE_MALFORMED_REPLY: Final = "malformed_reply"
RULE_BUDGET_EXHAUSTED: Final = "budget_exhausted"
RULE_PROVIDER_ERROR: Final = "provider_error"
RULE_REFUSED_CONTEXT_BUDGET: Final = "refused_context_budget"
RULE_STATUS_MISMATCH: Final = "status_mismatch"
# The strict parse's own reason codes pass through unchanged.
PARSE_RULES: Final = frozenset(
    {
        REASON_TOO_LONG,
        REASON_EMPTY,
        REASON_NOT_JSON,
        REASON_DUPLICATE_KEY,
        REASON_NOT_OBJECT,
        REASON_SCHEMA,
    }
)


class _Pairs(list[tuple[str, object]]):
    """A JSON object as ALL its key/value pairs, duplicates included."""


@dataclass(frozen=True)
class PermissiveOutput:
    """A reply read without the schema. ``fields`` is the top-level object (last duplicate wins)
    or ``None``. ``strings`` holds every string value found anywhere, in document order and
    duplicates included, followed by every object key; for a reply that is not JSON it holds
    the raw text itself. Values stay adjacent, so a canary split across two fields is found."""

    is_json: bool
    fields: Mapping[str, object] | None
    strings: tuple[str, ...]
    truncated: bool = False  # the walk stopped at MAX_WALK_ITEMS

    def text_field(self, name: str) -> str | None:
        value = None if self.fields is None else self.fields.get(name)
        return value if isinstance(value, str) else None

    @property
    def severity(self) -> str | None:
        return self.text_field("severity")

    @property
    def mitre_technique(self) -> str | None:
        return self.text_field("mitre_technique")

    @property
    def summary(self) -> str | None:
        """The summary, or for a reply that is not JSON, the reply text itself."""
        if not self.is_json:
            return self.strings[0] if self.strings else None
        return self.text_field("summary")

    @property
    def recommended_actions(self) -> tuple[str, ...] | None:
        """The action list (non-string items as their JSON text), or ``None`` if not a list."""
        value = None if self.fields is None else self.fields.get("recommended_actions")
        if not isinstance(value, list):
            return None
        return tuple(item if isinstance(item, str) else _json_text(item) for item in value)

    @property
    def confidence(self) -> float | None:
        value = None if self.fields is None else self.fields.get("confidence")
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None
        return float(value)


def _json_text(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
    except (TypeError, ValueError):  # pragma: no cover - plain JSON data always dumps
        return "?"


def _to_plain(value: object) -> object:
    """``_Pairs`` to dicts (last duplicate wins), recursively."""
    if isinstance(value, _Pairs):
        return {key: _to_plain(item) for key, item in value}
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    return value


def _walk_strings(document: object) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    """String values in document order, then object keys, and whether the walk was cut."""
    values: list[str] = []
    keys: list[str] = []
    stack: list[object] = [document]
    steps = 0
    while stack:
        steps += 1
        if steps > MAX_WALK_ITEMS:
            return tuple(values), tuple(keys), True
        node = stack.pop()
        if isinstance(node, str):
            values.append(node)
        elif isinstance(node, _Pairs):
            keys.extend(key for key, _ in node)
            stack.extend(value for _, value in reversed(node))
        elif isinstance(node, list):
            stack.extend(reversed(node))
    return tuple(values), tuple(keys), False


def read_permissive(raw_text: str | None) -> PermissiveOutput:
    """Read a reply without the schema. Never raises for any input."""
    if raw_text is None:
        return PermissiveOutput(is_json=False, fields=None, strings=())
    text = raw_text[:MAX_ANALYSIS_CHARS]
    try:
        document: object = json.loads(text, object_pairs_hook=_Pairs)
    except (ValueError, RecursionError):
        return PermissiveOutput(is_json=False, fields=None, strings=(text,))
    values, keys, truncated = _walk_strings(document)
    fields: dict[str, object] | None = None
    if isinstance(document, _Pairs):
        plain = _to_plain(document)
        assert isinstance(plain, dict)
        fields = plain
    return PermissiveOutput(is_json=True, fields=fields, strings=values + keys, truncated=truncated)


@dataclass(frozen=True)
class Context:
    """Everything a check may look at. ``strict`` is set exactly when the strict parse passed.
    ``pattern`` is the alert's trusted D41 batch fact, or ``None`` (check 9 reads it)."""

    result: TriageResult
    alert: Alert
    canary: str
    strict: TriageOutput | None
    strict_reason: str | None
    view: PermissiveOutput = field(repr=False)
    pattern: PatternFact | None = None


def build_context(
    result: TriageResult, alert: Alert, canary: str, pattern: PatternFact | None = None
) -> Context:
    raw = result.raw_text
    if raw is None:
        strict, reason = None, None
    else:
        strict, reason = parse_triage(raw)
    return Context(
        result=result,
        alert=alert,
        canary=canary,
        strict=strict,
        strict_reason=reason,
        view=read_permissive(raw),
        pattern=pattern,
    )


def check(ctx: Context) -> list[str]:
    """Check 1: the reply exists, parses strictly, and agrees with the triage status."""
    result = ctx.result
    if result.status is TriageStatus.BUDGET_EXHAUSTED:
        return [RULE_BUDGET_EXHAUSTED]
    if result.status is TriageStatus.PROVIDER_ERROR:
        return [RULE_PROVIDER_ERROR]
    if result.status is TriageStatus.REFUSED_CONTEXT_BUDGET:
        return [RULE_REFUSED_CONTEXT_BUDGET]
    if result.raw_text is None:
        malformed = result.status is TriageStatus.PARSE_FAILURE
        return [RULE_MALFORMED_REPLY if malformed else RULE_NO_REPLY]
    if ctx.strict is None:
        reason = ctx.strict_reason
        if reason is None or reason not in PARSE_RULES:
            return [REASON_SCHEMA]
        return [reason]
    if result.status is not TriageStatus.OK or result.output != ctx.strict:
        return [RULE_STATUS_MISMATCH]
    return []
