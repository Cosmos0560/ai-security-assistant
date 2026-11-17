"""Check 6: length limits on the reply and on every string in it (D12, T4, T8).

The strict schema already caps the summary and the action list; this check applies the same caps
to the permissive view, so an over-long reply gets a precise reason even when it is not
schema-valid, and it bounds the raw text and every other string.
"""

from __future__ import annotations

from typing import Final

from ai_security_assistant.schema import MAX_ACTIONS, SUMMARY_MAX_CHARS
from ai_security_assistant.triage import MAX_REPLY_CHARS
from ai_security_assistant.validator.schema import Context

MAX_STRING_CHARS: Final = SUMMARY_MAX_CHARS
MAX_STRINGS: Final = 64

RULE_RAW_TEXT: Final = "raw_text_too_long"
RULE_SUMMARY: Final = "summary_too_long"
RULE_ACTIONS: Final = "too_many_actions"
RULE_STRING: Final = "string_too_long"
RULE_STRINGS: Final = "too_many_strings"


def check(ctx: Context) -> list[str]:
    view = ctx.view
    rules: list[str] = []
    raw = ctx.result.raw_text
    if raw is not None and len(raw) > MAX_REPLY_CHARS:
        rules.append(RULE_RAW_TEXT)
    summary = view.text_field("summary")
    if summary is not None and len(summary) > SUMMARY_MAX_CHARS:
        rules.append(RULE_SUMMARY)
    actions = view.recommended_actions
    if actions is not None and len(actions) > MAX_ACTIONS:
        rules.append(RULE_ACTIONS)
    if view.is_json and any(len(text) > MAX_STRING_CHARS for text in view.strings):
        rules.append(RULE_STRING)
    if view.truncated or len(view.strings) > MAX_STRINGS:
        rules.append(RULE_STRINGS)
    return rules
