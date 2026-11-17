"""The triage output schema (D11): ONE closed JSON object, nothing else.

Five keys, no extras, strict types. ``recommended_actions`` is an enum list (the allowlist of D12
check 2 is the type itself); ``mitre_technique`` has the D12 check 3 ID shape. Whether a technique
exists, whether an IOC is grounded in the input and whether the canary leaked are Phase 5 checks;
the schema only fixes shape and size.

``tool_input_schema()`` is the JSON Schema that the Anthropic provider sends as the forced tool's
``input_schema``. It is derived from the model, so the two cannot drift.
"""

from __future__ import annotations

import copy
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

MITRE_ID_PATTERN: Final = r"^T\d{4}(\.\d{3})?$"
SUMMARY_MAX_CHARS: Final = 500
MAX_ACTIONS: Final = 8


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    """The recommendation allowlist. The assistant never executes any of them (D13)."""

    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    COLLECT_LOGS = "collect_logs"
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    RESET_CREDENTIALS = "reset_credentials"
    ESCALATE_TO_ANALYST = "escalate_to_analyst"
    CLOSE_AS_FALSE_POSITIVE = "close_as_false_positive"


class TriageOutput(BaseModel):
    """What the model must return for one alert."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    severity: Severity
    mitre_technique: str = Field(pattern=MITRE_ID_PATTERN)
    summary: str = Field(min_length=1, max_length=SUMMARY_MAX_CHARS)
    recommended_actions: list[Action] = Field(min_length=1, max_length=MAX_ACTIONS)
    confidence: float = Field(ge=0.0, le=1.0)


def _inline_refs(node: Any, defs: dict[str, Any]) -> Any:
    """Replace ``$ref`` pointers by the definitions they name and drop ``title`` noise."""
    if isinstance(node, dict):
        if "$ref" in node:
            return _inline_refs(copy.deepcopy(defs[node["$ref"].rsplit("/", 1)[-1]]), defs)
        return {k: _inline_refs(v, defs) for k, v in node.items() if k not in ("title", "$defs")}
    if isinstance(node, list):
        return [_inline_refs(item, defs) for item in node]
    return node


def tool_input_schema() -> dict[str, Any]:
    """A self-contained JSON Schema (no ``$ref``) for the five-key object."""
    raw = TriageOutput.model_json_schema()
    schema = _inline_refs(raw, raw.get("$defs", {}))
    assert isinstance(schema, dict)
    return schema
