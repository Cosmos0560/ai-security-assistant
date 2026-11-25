"""Check 3: ``mitre_technique`` by ID shape plus a small offline allowlist (D12).

The allowlist is ``data/mitre_allowlist.json``: every technique the mock's table can produce plus
a small set of techniques common in SOC alerts. It is package data, read once; there is no
network call to MITRE. A well-formed ID that is not on the list goes to human review: the list
is deliberately small, and a reviewer can extend it.

The file is also the ONE source for what the model is told it may answer: the system prompts list
``techniques()`` and the Ollama request's schema takes ``allowlist()`` as an enum. Neither replaces
this check, which is the guarantee.
"""

from __future__ import annotations

import functools
import json
import re
from importlib import resources
from typing import Final

from ai_security_assistant.schema import MITRE_ID_PATTERN
from ai_security_assistant.validator.schema import Context

ALLOWLIST_PACKAGE: Final = "ai_security_assistant"
ALLOWLIST_PATH: Final = ("data", "mitre_allowlist.json")
_ID_RE: Final = re.compile(MITRE_ID_PATTERN)

RULE_MISSING: Final = "missing"
RULE_BAD_FORMAT: Final = "bad_format"
RULE_NOT_ALLOWLISTED: Final = "not_allowlisted"


def parse_techniques(text: str) -> dict[str, str]:
    """``ID -> short name`` of an allowlist document, in file order. ``ValueError`` on a defect."""
    document = json.loads(text)
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("mitre allowlist: version must be 1")
    techniques = document.get("techniques")
    if not isinstance(techniques, dict) or not techniques:
        raise ValueError("mitre allowlist: techniques must be a non-empty object")
    for technique_id, name in techniques.items():
        if not _ID_RE.fullmatch(technique_id) or not isinstance(name, str) or not name:
            raise ValueError("mitre allowlist: bad entry")
    return dict(techniques)


def parse_allowlist(text: str) -> frozenset[str]:
    """The technique IDs of an allowlist document. Raises ``ValueError`` on any defect."""
    return frozenset(parse_techniques(text))


@functools.cache
def _packaged() -> tuple[tuple[str, str], ...]:
    resource = resources.files(ALLOWLIST_PACKAGE).joinpath(*ALLOWLIST_PATH)
    return tuple(parse_techniques(resource.read_text(encoding="utf-8")).items())


def techniques() -> dict[str, str]:
    """``ID -> short name`` of the packaged allowlist (a fresh copy)."""
    return dict(_packaged())


def allowlist() -> frozenset[str]:
    return frozenset(technique_id for technique_id, _name in _packaged())


def check(ctx: Context) -> list[str]:
    view = ctx.view
    if view.fields is None:
        return []  # not a JSON object: check 1 already says so
    if "mitre_technique" not in view.fields:
        return [RULE_MISSING]
    technique = view.mitre_technique
    if technique is None or not _ID_RE.fullmatch(technique):
        return [RULE_BAD_FORMAT]
    if technique not in allowlist():
        return [RULE_NOT_ALLOWLISTED]
    return []
