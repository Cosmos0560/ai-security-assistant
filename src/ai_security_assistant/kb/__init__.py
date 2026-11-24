"""The Windows knowledge base (D39): trusted facts, keyed by strict structured fields.

``data/windows_kb.json`` is the ONLY place a Windows event, logon-type or status meaning is
written. This module loads it with a strict model (a malformed file fails closed with
``KbError``) and looks facts up for one alert.

The keys come from five untrusted ``Alert`` fields (``event_id``, ``logon_type``, ``status``,
``sub_status`` and ``target_user``). A key is used only when it has the exact canonical shape
below; anything else (padding, sign, a stray space, free text) gives no fact. Nothing is ever
parsed out of ``message`` or any other free text, and no alert text is copied into a fact: a fact
is table text, a table code, or an integer counted by code.

Residual risk (T14): whoever writes the log can choose a different REAL code, and then gets that
code's true but possibly misleading facts. The fact says what the code means, not that the code
is right.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from typing import Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ai_security_assistant.models import Alert
from ai_security_assistant.schema import MITRE_ID_PATTERN

KB_PACKAGE: Final = "ai_security_assistant"
KB_PATH: Final = ("data", "windows_kb.json")
SCHEMA_VERSION: Final = 1
MAX_ALIASES: Final = 16

# Canonical key shapes (D39). ASCII digits only (``\d`` would also match other scripts), no
# leading zero, no sign, no space.
_EVENT_ID_RE: Final = re.compile(r"(?:0|[1-9][0-9]{0,4})")
_LOGON_TYPE_RE: Final = re.compile(r"(?:0|[1-9][0-9]?)")
_STATUS_RE: Final = re.compile(r"0x[0-9A-Fa-f]{8}")
_STATUS_CANONICAL_RE: Final = re.compile(r"0x[0-9A-F]{8}")
_VERSION_RE: Final = re.compile(r"[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}")
_ALIAS_RE: Final = re.compile(r"[a-z0-9][a-z0-9 .'-]{0,63}")
_TECHNIQUE_RE: Final = re.compile(MITRE_ID_PATTERN)

FactKind = Literal["event", "logon_type", "status", "sub_status"]
PatternName = Literal["password_spraying", "brute_force", "undetermined"]


class KbError(Exception):
    """The knowledge base file is missing or malformed. The message is a fixed phrase."""


def canonical_event_id(raw: object) -> str | None:
    """The event ID when ``raw`` is a plain decimal of 1 to 5 digits, else ``None``."""
    if isinstance(raw, str) and _EVENT_ID_RE.fullmatch(raw) is not None:
        return raw
    return None


def canonical_logon_type(raw: object) -> str | None:
    """The logon type when ``raw`` is a plain decimal of 1 or 2 digits, else ``None``."""
    if isinstance(raw, str) and _LOGON_TYPE_RE.fullmatch(raw) is not None:
        return raw
    return None


def canonical_status(raw: object) -> str | None:
    """``0x`` plus 8 hex digits, with the digits folded to upper case, else ``None``."""
    if isinstance(raw, str) and _STATUS_RE.fullmatch(raw) is not None:
        return "0x" + raw[2:].upper()
    return None


# --------------------------------------------------------------------------- the file model


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class _Entry(_Strict):
    name: str = Field(min_length=1, max_length=120)
    meaning: str = Field(min_length=1, max_length=480)
    aliases: tuple[str, ...] = Field(min_length=1, max_length=MAX_ALIASES)
    source: str = Field(min_length=1, max_length=400)

    @model_validator(mode="after")
    def _aliases_are_clean(self) -> Self:
        for alias in self.aliases:
            if _ALIAS_RE.fullmatch(alias) is None:
                raise ValueError("alias must be lower case, ASCII, 1 to 64 characters")
        if len(set(self.aliases)) != len(self.aliases):
            raise ValueError("duplicate alias inside one entry")
        return self


class EventEntry(_Entry):
    never_records: tuple[str, ...] = Field(max_length=8)


class LogonTypeEntry(_Entry):
    pass


class StatusEntry(_Entry):
    pass


class SprayingRule(_Strict):
    technique: str
    min_distinct_users: int = Field(ge=2, le=1000)
    max_attempts_per_user: int = Field(ge=1, le=1000)
    meaning: str = Field(min_length=1, max_length=480)


class BruteForceRule(_Strict):
    technique: str
    distinct_users: int = Field(ge=1, le=1000)
    min_attempts: int = Field(ge=2, le=100_000)
    meaning: str = Field(min_length=1, max_length=480)


class UndeterminedRule(_Strict):
    meaning: str = Field(min_length=1, max_length=480)


class Patterns(_Strict):
    """The D41 thresholds. They live in the data file, not in code."""

    event_id: str
    window_seconds: int = Field(ge=1, le=86_400)
    password_spraying: SprayingRule
    brute_force: BruteForceRule
    undetermined: UndeterminedRule

    @model_validator(mode="after")
    def _rules_are_exclusive(self) -> Self:
        if canonical_event_id(self.event_id) is None:
            raise ValueError("patterns.event_id is not a canonical event ID")
        for technique in (self.password_spraying.technique, self.brute_force.technique):
            if _TECHNIQUE_RE.fullmatch(technique) is None:
                raise ValueError("pattern technique is not a MITRE technique ID")
        # A group can match at most one rule: spraying needs more users than brute force allows.
        if self.brute_force.distinct_users >= self.password_spraying.min_distinct_users:
            raise ValueError("the spraying and brute-force rules overlap")
        return self


class KnowledgeBase(_Strict):
    schema_version: Literal[1]
    kb_version: str
    about: str = Field(min_length=1, max_length=1000)
    events: Mapping[str, EventEntry] = Field(min_length=1)
    logon_types: Mapping[str, LogonTypeEntry] = Field(min_length=1)
    statuses: Mapping[str, StatusEntry] = Field(min_length=1)
    patterns: Patterns

    @model_validator(mode="after")
    def _keys_and_aliases(self) -> Self:
        if _VERSION_RE.fullmatch(self.kb_version) is None:
            raise ValueError("kb_version must look like 2026.11.1")
        for key in self.events:
            if canonical_event_id(key) != key:
                raise ValueError("event key is not a canonical event ID")
        for key in self.logon_types:
            if canonical_logon_type(key) != key:
                raise ValueError("logon type key is not canonical")
        for key in self.statuses:
            if _STATUS_CANONICAL_RE.fullmatch(key) is None:
                raise ValueError("status key is not canonical (0x plus 8 upper-case hex digits)")
        if self.patterns.event_id not in self.events:
            raise ValueError("patterns.event_id is not an event in the table")
        for table in (self.events, self.logon_types, self.statuses):
            seen: set[str] = set()
            for entry in table.values():
                for alias in entry.aliases:
                    if alias in seen:
                        raise ValueError("an alias names two entries of one table")
                    seen.add(alias)
        return self


def parse_kb(text: str) -> KnowledgeBase:
    """The knowledge base in ``text``. Any defect raises ``KbError`` with a fixed message."""
    try:
        return KnowledgeBase.model_validate_json(text)
    except ValidationError:
        raise KbError("the Windows knowledge base file is malformed") from None


@functools.cache
def load_kb() -> KnowledgeBase:
    """The packaged table, read once. Raises ``KbError`` when it is missing or malformed."""
    try:
        resource = resources.files(KB_PACKAGE).joinpath(*KB_PATH)
        text = resource.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise KbError("the Windows knowledge base file cannot be read") from None
    return parse_kb(text)


# --------------------------------------------------------------------------- the facts


@dataclass(frozen=True)
class Fact:
    """One table entry that applies to an alert. Table text only."""

    kind: FactKind
    code: str
    name: str
    meaning: str
    never_records: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "code": self.code,
            "name": self.name,
            "meaning": self.meaning,
            "never_records": list(self.never_records),
        }


@dataclass(frozen=True)
class PatternFact:
    """The D41 outcome for one source-address group. Table text plus counted integers."""

    pattern: PatternName
    technique: str | None
    meaning: str
    window_seconds: int
    distinct_users: int
    max_attempts_per_user: int
    attempts: int

    def to_dict(self) -> dict[str, object]:
        return {
            "pattern": self.pattern,
            "technique": self.technique,
            "meaning": self.meaning,
            "window_seconds": self.window_seconds,
            "distinct_users": self.distinct_users,
            "max_attempts_per_user": self.max_attempts_per_user,
            "attempts": self.attempts,
        }


@dataclass(frozen=True)
class ReferenceFacts:
    """Every fact for one alert: event, logon type, status, sub status, then the pattern."""

    kb_version: str
    facts: tuple[Fact, ...]
    pattern: PatternFact | None

    def to_dict(self) -> dict[str, object]:
        return {
            "kb_version": self.kb_version,
            "facts": [fact.to_dict() for fact in self.facts],
            "pattern": None if self.pattern is None else self.pattern.to_dict(),
        }


def reference_facts(
    alert: Alert, pattern: PatternFact | None = None, kb: KnowledgeBase | None = None
) -> ReferenceFacts | None:
    """The trusted facts for ``alert``, or ``None`` when no key matches the table.

    Only the strict key fields are read. ``target_user`` and every free-text field are never
    consulted, so nothing an attacker writes can become fact text.
    """
    table = load_kb() if kb is None else kb
    facts: list[Fact] = []
    event_id = canonical_event_id(alert.event_id)
    if event_id is not None and (event := table.events.get(event_id)) is not None:
        facts.append(Fact("event", event_id, event.name, event.meaning, event.never_records))
    logon_type = canonical_logon_type(alert.logon_type)
    if logon_type is not None and (logon := table.logon_types.get(logon_type)) is not None:
        facts.append(Fact("logon_type", logon_type, logon.name, logon.meaning))
    code = canonical_status(alert.status)
    if code is not None and (status := table.statuses.get(code)) is not None:
        facts.append(Fact("status", code, status.name, status.meaning))
    code = canonical_status(alert.sub_status)
    if code is not None and (status := table.statuses.get(code)) is not None:
        facts.append(Fact("sub_status", code, status.name, status.meaning))
    if not facts and pattern is None:
        return None
    return ReferenceFacts(kb_version=table.kb_version, facts=tuple(facts), pattern=pattern)
