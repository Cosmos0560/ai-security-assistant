"""Check 2: ``recommended_actions`` only from the allowlist enum (D12, D13).

The strict parse already refuses an action outside ``schema.Action``, but only as a generic
schema violation. This check reads the permissive view of the reply, so the reason says what
actually went wrong. The off-list value itself is never reported.
"""

from __future__ import annotations

from typing import Final

from ai_security_assistant.schema import Action
from ai_security_assistant.validator.schema import Context

ALLOWED: Final = frozenset(action.value for action in Action)

RULE_MISSING: Final = "missing"
RULE_NOT_A_LIST: Final = "not_a_list"
RULE_OFF_ALLOWLIST: Final = "off_allowlist"


def check(ctx: Context) -> list[str]:
    view = ctx.view
    if view.fields is None:
        return []  # not a JSON object: check 1 already says so
    if "recommended_actions" not in view.fields:
        return [RULE_MISSING]
    actions = view.recommended_actions
    if actions is None:
        return [RULE_NOT_A_LIST]
    if any(action not in ALLOWED for action in actions):
        return [RULE_OFF_ALLOWLIST]
    return []
