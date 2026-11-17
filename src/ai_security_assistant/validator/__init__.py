"""The output validator (D12): eight ordered checks, fail closed to ``needs_human_review``.

Input: the ``TriageResult`` (its ``raw_text`` included) and the ORIGINAL ``Alert``, plus the
run's canary. Checks, in order:

1. ``schema``    the reply parses strictly into ``TriageOutput`` and agrees with the status;
2. ``actions``   every recommended action is on the allowlist enum;
3. ``mitre``     the technique has the ID shape and is on the offline allowlist;
4. ``grounding`` every IP, domain, URL and hash in the output appears in the alert;
5. ``canary``    the run's canary is not in the reply (``detector/canary.py`` matching);
6. ``limits``    the reply and every string in it are within the length limits;
7. ``secrets``   the vendored secret-scanner finds nothing in the reply;
8. ``severity``  the severity is not below the floor from the source's own severity (D33).

Every check runs, and every failure is reported, so a reply that already failed the strict parse
still gets precise reasons from the permissive reading (see ``validator/schema.py``). Any failed
check, and any exception inside a check or while reading the reply, gives
``needs_human_review``. There is no partial result: an accepted result carries the strict
output, and a rejected one carries none.

Reason codes are machine-readable, ``<check>.<rule>``: the check name and a rule id from a fixed
set (for check 7, a vendored scanner rule id). They never contain text from the reply or the
alert.

The validator is optional by design (the D22 ablation): with it OFF, ``pipeline.py`` reads the
reply with ``read_permissive`` and reports whatever the model produced.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from ai_security_assistant.detector.canary import canary_leaked
from ai_security_assistant.models import Alert
from ai_security_assistant.schema import TriageOutput
from ai_security_assistant.triage import TriageResult
from ai_security_assistant.validator import (
    actions,
    grounding,
    limits,
    mitre,
    schema,
    secrets,
    severity,
)
from ai_security_assistant.validator.schema import (
    Context,
    PermissiveOutput,
    build_context,
    read_permissive,
)

RULE_EXCEPTION: Final = "exception"
RULE_LEAKED: Final = "leaked"
RULE_NO_STRICT_OUTPUT: Final = "no_strict_output"
VALIDATOR: Final = "validator"  # the pseudo-check for a failure outside any check


class Verdict(StrEnum):
    ACCEPTED = "accepted"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


@dataclass(frozen=True)
class ValidationResult:
    """``output`` is set exactly when ``verdict`` is ``accepted``; ``reasons`` are codes."""

    verdict: Verdict
    output: TriageOutput | None = None
    reasons: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        return self.verdict is Verdict.ACCEPTED


def check_canary(ctx: Context) -> list[str]:
    """Check 5: the canary, also spaced, disguised or split across strings."""
    texts = [ctx.result.raw_text or "", *ctx.view.strings]
    return [RULE_LEAKED] if canary_leaked(ctx.canary, texts) else []


Check = Callable[[Context], list[str]]

CHECKS: tuple[tuple[str, Check], ...] = (
    ("schema", schema.check),
    ("actions", actions.check),
    ("mitre", mitre.check),
    ("grounding", grounding.check),
    ("canary", check_canary),
    ("limits", limits.check),
    ("secrets", secrets.check),
    ("severity", severity.check),
)


def _review(reasons: list[str]) -> ValidationResult:
    return ValidationResult(Verdict.NEEDS_HUMAN_REVIEW, None, tuple(dict.fromkeys(reasons)))


def validate(result: TriageResult, alert: Alert, canary: str) -> ValidationResult:
    """Run every check in order. Never raises; fails closed."""
    try:
        ctx = build_context(result, alert, canary)
    except Exception:
        return _review([f"{VALIDATOR}.{RULE_EXCEPTION}"])
    reasons: list[str] = []
    for name, check in CHECKS:
        try:
            rules = check(ctx)
        except Exception:
            rules = [RULE_EXCEPTION]
        reasons.extend(f"{name}.{rule}" for rule in rules)
    if ctx.strict is None and not reasons:
        reasons.append(f"{VALIDATOR}.{RULE_NO_STRICT_OUTPUT}")  # never accept without it
    if reasons:
        return _review(reasons)
    return ValidationResult(Verdict.ACCEPTED, ctx.strict, ())


__all__ = [
    "CHECKS",
    "Context",
    "PermissiveOutput",
    "ValidationResult",
    "Verdict",
    "check_canary",
    "read_permissive",
    "validate",
]
