"""Check 9: every Windows fact in the reply must agree with the knowledge base (D42, T12).

The reply is read the way check 4 reads it: every string (keys included; the raw text when the
reply is not JSON), after the same normalization (``grounding.normalize``: sanitizer
normalization, case folding, refanging), applied line by line so that line breaks survive (the
sanitizer turns them into spaces, and a line break ends a clause here). Markdown emphasis (``*``
and backticks) is dropped, an ellipsis becomes a space, and the abbreviations "e.g.", "i.e.",
"etc.", "vs." and "cf." lose their dots, so none of them ends a sentence.

Mentions (strict shapes, anchored by context; nothing is guessed out of a bare number):

* an event ID: ``event``, ``event id``, ``eventid`` or ``eid`` followed by 1 to 5 digits. A bare
  number (a port, a year, a rule ID) is never an event ID;
* a logon type: ``logon type`` followed by 1 or 2 digits; and, on a line that names a logon type
  anyway, a list item such as ``10 for "x"``, ``10 = x``, ``10: x`` or ``10 (x)`` whose text is
  an alias in the logon-type table (the markdown-table form of the recorded hallucination);
* a status: every ``0x`` plus 8 hex digits.

Rules, as ``kb.<rule>`` reason codes:

* ``unknown_<kind>``: the code is not in the table. Fail closed (as the MITRE allowlist);
  widening the table is a data change.
* ``ungrounded_<kind>``: the code is in the table but is not the alert's own value (its
  ``event_id``, ``logon_type``, ``status`` or ``sub_status`` field, strict shapes only). This is
  IOC grounding (T5) applied to facts. A code in the alert's free text does not ground it.
* ``contradiction_<kind>``: the code's clause names an alias of a DIFFERENT entry of the same
  table (events, logon types and statuses are separate tables). The clause runs from the code to
  the first of: the next code mention, the end of the sentence (``.``, ``!``, ``?``, ``;`` before
  a space, or a line break), or ``MAX_CLAUSE_CHARS``. It continues into the next sentence only
  when that sentence opens with a back-reference ("this code", "the error code", "that status",
  "it" ...). A code joined to the text before it by an opening parenthesis or a dash ("the
  password is wrong (0xc0000064)", "rdp logon (logon type 3)", "bad password - status
  0xc000006a") also owns the clause before it, back to the first of: the previous code
  mention, a sentence end or line break, a comma, a colon, a closing parenthesis, or
  ``MAX_CLAUSE_CHARS`` (Phase 10b). Aliases are matched longest first, so "remote interactive"
  is never read as "interactive" and "network cleartext" never as "network".
* ``contradiction_pattern``: the technique is the brute-force technique while the D41 batch fact
  says password spraying, or the reverse (techniques read from the table).
* ``unsupported_pattern``: the D41 fact is ``undetermined`` (the table tells the model not to
  name either technique) and the technique is one of the two anyway. Alerts with no pattern fact
  are not checked.
* ``not_recorded_claim``: the alert's event has ``never_records`` items in the table, and the
  reply attributes that content to the log ("the attempted password was", "each attempt used a
  different password", "the event shows the password", "the logged password was"). Generic
  attacker-behaviour wording ("the attacker is trying different passwords") is not a claim
  about the log and passes.

Residual risk (README "What it can't do"), by design: a misstatement with no code in its clause
passes ("the user lacks the right to log on here"), as does a line such as "different
passwords are tried in sequence", and so does a meaning joined to a wrong code by a colon or a
bare space only ("wrong password: 0xc0000064"). The report's reference-facts section is the
mitigation: the analyst sees the table's meaning next to the model's summary. The other way
round, a correct sentence that names a second entry in the code's clause ("event 4740 after
five failed logon attempts", "logon type 10, not interactive") goes to review: fail closed over
fluent.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from ai_security_assistant.kb import (
    KnowledgeBase,
    PatternFact,
    canonical_event_id,
    canonical_logon_type,
    canonical_status,
    load_kb,
)
from ai_security_assistant.models import Alert
from ai_security_assistant.validator.grounding import normalize
from ai_security_assistant.validator.schema import Context

Kind = Literal["event_id", "logon_type", "status"]
KINDS: Final[tuple[Kind, ...]] = ("event_id", "logon_type", "status")
RULE_CONTRADICTION_PATTERN: Final = "contradiction_pattern"
RULE_UNSUPPORTED_PATTERN: Final = "unsupported_pattern"
RULE_NOT_RECORDED: Final = "not_recorded_claim"
RULES: Final[tuple[str, ...]] = (
    *(f"unknown_{kind}" for kind in KINDS),
    *(f"ungrounded_{kind}" for kind in KINDS),
    *(f"contradiction_{kind}" for kind in KINDS),
    RULE_CONTRADICTION_PATTERN,
    RULE_UNSUPPORTED_PATTERN,
    RULE_NOT_RECORDED,
)
MAX_CLAUSE_CHARS: Final = 200  # per sentence; a back-reference adds at most one more sentence

_MARKUP_RE: Final = re.compile(r"[*`]")
_ABBREVIATION_RE: Final = re.compile(r"\b(?:e\.g|i\.e|etc|vs|cf)\.")
_ELLIPSIS_RE: Final = re.compile(r"\.{2,}")  # NFKC has already turned "…" into "..."
# The digits end where the number ends: not inside a date, a time, an address or a longer number.
_NUMBER_END: Final = r"(?![0-9]|[.,:/-][0-9])"
_GAP: Final = r"""[\s:#=("'-]{0,4}"""
_EVENT_RE: Final = re.compile(
    r"(?<![a-z0-9])(?:event\s*ids?|events?|eids?)" + _GAP + r"([0-9]{1,5})" + _NUMBER_END
)
_LOGON_ANCHOR: Final = r"(?<![a-z0-9])logon\s*types?"
_LOGON_ANCHOR_RE: Final = re.compile(_LOGON_ANCHOR)
_LOGON_RE: Final = re.compile(_LOGON_ANCHOR + _GAP + r"([0-9]{1,2})" + _NUMBER_END)
_LIST_ITEM: Final = r"""(?<![\w.])([0-9]{1,2})\s*(?:(?:for\b|=>|->|=|:|-)\s*["'(]?|["'(])\s*"""
_STATUS_RE: Final = re.compile(r"(?<![0-9a-z])(0x[0-9a-f]{8})(?![0-9a-z])")
_TERMINATOR_RE: Final = re.compile(r"\n|[.!?;](?=\s|$)")
_BACK_REFERENCE_RE: Final = re.compile(
    r"\s*(?:(?:this|that|the)\s+(?:error\s+)?(?:code|status|value)|it)(?![a-z0-9])"
)


_BACK_BOUNDARY_RE: Final = re.compile(r"\n|[.!?;](?=\s|$)|[,:)]")
# What joins a code to the clause before it: an opening parenthesis or a dash, then at most a
# status label ("(status 0x...", "- sub status: 0x..."). A colon alone ("wrong password:
# 0x...") or a bare space does not join (label form, and a list such as "logon type 3 network
# logon and logon type 10" would otherwise read the first entry's words as the second's).
_JOINT_RE: Final = re.compile(
    r"(?:\(|(?<!\S)-{1,2}|[–—])\s*"
    r"(?:(?:sub\s*)?status(?:\s+code)?|(?:error\s+)?code)?[\s:=#]*\Z"
)


@dataclass(frozen=True)
class Mention:
    kind: Kind
    code: str  # as written, case-folded; canonical form is decided against the table
    start: int
    end: int
    anchor: int  # where the whole mention starts ("event", "logon type", the list number, "0x")


def kb_text(text: str) -> str:
    """The text the mentions and clauses are read from (one normalization for both)."""
    lines = "\n".join(normalize(line) for line in text.splitlines())
    folded = _ELLIPSIS_RE.sub(" ", _MARKUP_RE.sub("", lines))
    return _ABBREVIATION_RE.sub(lambda match: match.group(0).replace(".", ""), folded)


def _alias_pattern(aliases: Iterable[str]) -> str:
    """One alternation, longest alias first, whole words only, any run of spaces between."""
    ordered = sorted(set(aliases), key=lambda alias: (-len(alias), alias))
    body = "|".join(r"\s+".join(re.escape(word) for word in alias.split()) for alias in ordered)
    return r"(?<![a-z0-9])(?:" + body + r")(?![a-z0-9])"


class _HasAliases(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def meaning(self) -> str: ...
    @property
    def aliases(self) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class _Table:
    """One KB table as matchers: alias -> code, and the alternation regex."""

    owner: Mapping[str, str]
    regex: re.Pattern[str]

    @classmethod
    def build(cls, entries: Mapping[str, _HasAliases]) -> _Table:
        owner = {alias: code for code, entry in entries.items() for alias in entry.aliases}
        return cls(owner, re.compile(_alias_pattern(owner)))

    def codes_in(self, window: str) -> set[str]:
        return {
            self.owner[" ".join(match.group(0).split())] for match in self.regex.finditer(window)
        }


@dataclass(frozen=True)
class _Matchers:
    tables: Mapping[Kind, _Table]
    list_item: re.Pattern[str]


_LAST: list[tuple[KnowledgeBase, _Matchers]] = []  # the matchers of the last table used


def _matchers(kb: KnowledgeBase) -> _Matchers:
    if _LAST and _LAST[0][0] is kb:
        return _LAST[0][1]
    tables: dict[Kind, _Table] = {
        "event_id": _Table.build(kb.events),
        "logon_type": _Table.build(kb.logon_types),
        "status": _Table.build(kb.statuses),
    }
    logon_aliases = _alias_pattern(tables["logon_type"].owner)
    matchers = _Matchers(tables, re.compile(_LIST_ITEM + "(?=" + logon_aliases + ")"))
    _LAST[:] = [(kb, matchers)]
    return matchers


def mentions(text: str, matchers: _Matchers) -> list[Mention]:
    """Every code mention in ``text`` (already ``kb_text``), in order of position."""
    found: dict[int, Mention] = {}
    for match in _EVENT_RE.finditer(text):
        found[match.start(1)] = Mention(
            "event_id", match.group(1), match.start(1), match.end(1), match.start()
        )
    for match in _LOGON_RE.finditer(text):
        found[match.start(1)] = Mention(
            "logon_type", match.group(1), match.start(1), match.end(1), match.start()
        )
    for anchor in _LOGON_ANCHOR_RE.finditer(text):
        line_end = text.find("\n", anchor.end())
        stop = len(text) if line_end == -1 else line_end
        for match in matchers.list_item.finditer(text, anchor.end(), stop):
            start = match.start(1)
            found.setdefault(
                start, Mention("logon_type", match.group(1), start, match.end(1), start)
            )
    for match in _STATUS_RE.finditer(text):
        found[match.start(1)] = Mention(
            "status", match.group(1), match.start(1), match.end(1), match.start(1)
        )
    return [found[start] for start in sorted(found)]


def _sentence(text: str, start: int, limit: int) -> tuple[str, int | None]:
    """The text from ``start`` to the end of its sentence (capped), and where the next one starts
    (``None`` when the sentence was cut by ``limit`` or the cap, or the text ends)."""
    cap = min(limit, start + MAX_CLAUSE_CHARS)
    terminator = _TERMINATOR_RE.search(text, start, cap)
    if terminator is None:
        return text[start:cap], None
    following = terminator.end()
    return text[start : terminator.start()], following if following < limit else None


def clause(text: str, mention: Mention, next_start: int) -> str:
    """The clause that belongs to ``mention`` (see the module docstring)."""
    first, following = _sentence(text, mention.end, next_start)
    if following is None:
        return first
    if _BACK_REFERENCE_RE.match(text, following) is None:
        return first
    second, _ = _sentence(text, following, next_start)
    return f"{first} {second}"


def back_clause(text: str, mention: Mention, previous_end: int) -> str:
    """The clause right before ``mention`` when the code is joined to it ("bad password
    (0xc000006a)", "rdp - logon type 10"), else "". It runs back from the joint to the first of:
    the previous code mention, a sentence end or line break, a comma, a colon, a closing
    parenthesis, or ``MAX_CLAUSE_CHARS``."""
    lo = max(previous_end, mention.anchor - MAX_CLAUSE_CHARS)
    head = text[lo : mention.anchor]
    joint = _JOINT_RE.search(head)
    if joint is None:
        return ""
    head = head[: joint.start()]
    boundaries = [match.end() for match in _BACK_BOUNDARY_RE.finditer(head)]
    return head[boundaries[-1] :] if boundaries else head


def _canonical(kind: Kind, code: str) -> str | None:
    if kind == "event_id":
        return canonical_event_id(code)
    if kind == "logon_type":
        return canonical_logon_type(code)
    return canonical_status(code)


def _entries(kind: Kind, kb: KnowledgeBase) -> Mapping[str, _HasAliases]:
    if kind == "event_id":
        return kb.events
    if kind == "logon_type":
        return kb.logon_types
    return kb.statuses


def own_codes(alert: Alert) -> dict[Kind, set[str]]:
    """The alert's own codes, strict shapes only (the same keys the reference facts use)."""

    def present(*codes: str | None) -> set[str]:
        return {code for code in codes if code is not None}

    return {
        "event_id": present(canonical_event_id(alert.event_id)),
        "logon_type": present(canonical_logon_type(alert.logon_type)),
        "status": present(canonical_status(alert.status), canonical_status(alert.sub_status)),
    }


# --------------------------------------------------------------------------- grounded echo

_MEANING_SENTENCE_RE: Final = re.compile(r"(?<=[.!?;])\s+")
_KEPT: Final = frozenset(".!?;")  # a blanked echo keeps its sentence ends (and its whitespace)
_BLANK: Final = "\x00"  # never a word character, a space or a terminator


@dataclass(frozen=True)
class Echo:
    """A span of the reply that reproduces table text of one of the alert's own entries."""

    kind: Kind
    code: str
    start: int
    end: int

    def holds(self, mention: Mention) -> bool:
        return self.start <= mention.start and mention.end <= self.end


def _phrase_regex(phrase: str) -> re.Pattern[str] | None:
    """``phrase`` (already ``kb_text``) as whole words, any run of spaces, no final period."""
    words = phrase.strip().rstrip(".!?;").split()
    if not words:
        return None
    return re.compile(r"(?<![a-z0-9])" + r"\s+".join(map(re.escape, words)) + r"(?![a-z0-9])")


def echo_patterns(alert: Alert, kb: KnowledgeBase) -> list[tuple[re.Pattern[str], Kind, str]]:
    """The name, the meaning and each meaning sentence of every entry in the alert's own
    reference facts, longest first. Table text only."""
    found: dict[str, tuple[Kind, str]] = {}
    for kind, codes in own_codes(alert).items():
        table = _entries(kind, kb)
        for code in sorted(codes):
            entry = table.get(code)
            if entry is None:
                continue
            meaning = kb_text(entry.meaning)
            for phrase in (kb_text(entry.name), meaning, *_MEANING_SENTENCE_RE.split(meaning)):
                found.setdefault(phrase.strip().rstrip(".!?;"), (kind, code))
    patterns = []
    for phrase in sorted(found, key=lambda text: (-len(text), text)):
        regex = _phrase_regex(phrase)
        if regex is not None:
            patterns.append((regex, *found[phrase]))
    return patterns


def echo_spans(text: str, patterns: Sequence[tuple[re.Pattern[str], Kind, str]]) -> list[Echo]:
    """Non-overlapping echo spans in ``text``, longest phrase first, in order of position."""
    taken: list[Echo] = []
    for regex, kind, code in patterns:
        for match in regex.finditer(text):
            if not any(match.start() < echo.end and echo.start < match.end() for echo in taken):
                taken.append(Echo(kind, code, match.start(), match.end()))
    return sorted(taken, key=lambda echo: echo.start)


def _attached(echo: Echo, text: str, outside: Sequence[Mention]) -> list[Mention]:
    """The codes an echo is attached to: the nearest mention before it on the same line, and
    the nearest one after it in the same sentence."""
    before = [m for m in outside if m.end <= echo.start and "\n" not in text[m.end : echo.start]]
    after = [
        m
        for m in outside
        if m.start >= echo.end and _TERMINATOR_RE.search(text, echo.end, m.start) is None
    ]
    return before[-1:] + after[:1]


def grounded_echoes(
    text: str, found: Sequence[Mention], alert: Alert, kb: KnowledgeBase
) -> list[Echo]:
    """The echo spans attached to their own entry's code, or to no code at all. An entry's
    words next to a DIFFERENT code are a claim about that code and stay in the scan."""
    spans = echo_spans(text, echo_patterns(alert, kb))
    outside = [m for m in found if not any(echo.holds(m) for echo in spans)]
    return [
        echo
        for echo in spans
        if all(
            m.kind == echo.kind and _canonical(m.kind, m.code) == echo.code
            for m in _attached(echo, text, outside)
        )
    ]


def blank(text: str, spans: Iterable[Echo]) -> str:
    """``text`` with every span's characters replaced, except whitespace and sentence ends."""
    chars = list(text)
    for span in spans:
        for index in range(span.start, span.end):
            if not (chars[index].isspace() or chars[index] in _KEPT):
                chars[index] = _BLANK
    return "".join(chars)


# --------------------------------------------------------------------------- the rules


def _code_rules(texts: Iterable[str], alert: Alert, kb: KnowledgeBase, echo: bool) -> set[str]:
    matchers = _matchers(kb)
    own = own_codes(alert)
    rules: set[str] = set()
    for raw in texts:
        text = kb_text(raw)
        found = mentions(text, matchers)
        if echo:
            grounded = grounded_echoes(text, found, alert, kb)
            if grounded:
                text = blank(text, grounded)
                found = mentions(text, matchers)
        for index, mention in enumerate(found):
            code = _canonical(mention.kind, mention.code)
            if code is None or code not in _entries(mention.kind, kb):
                rules.add(f"unknown_{mention.kind}")
                continue
            if code not in own[mention.kind]:
                rules.add(f"ungrounded_{mention.kind}")
            next_start = found[index + 1].start if index + 1 < len(found) else len(text)
            previous_end = found[index - 1].end if index else 0
            table = matchers.tables[mention.kind]
            named = table.codes_in(clause(text, mention, next_start)) | table.codes_in(
                back_clause(text, mention, previous_end)
            )
            if named - {code}:
                rules.add(f"contradiction_{mention.kind}")
    return rules


def _pattern_rules(
    technique: str | None, pattern: PatternFact | None, kb: KnowledgeBase
) -> set[str]:
    if pattern is None or technique is None:
        return set()
    claimed = technique.strip().upper()
    if claimed not in {kb.patterns.password_spraying.technique, kb.patterns.brute_force.technique}:
        return set()
    if pattern.technique is None:
        return {RULE_UNSUPPORTED_PATTERN}
    return set() if claimed == pattern.technique else {RULE_CONTRADICTION_PATTERN}


def _not_recorded_patterns(noun: str) -> Sequence[re.Pattern[str]]:
    """Phrases that attribute ``noun`` content to the log itself. ``noun`` is table text."""
    n = re.escape(noun)
    s = r"\s+"
    return tuple(
        re.compile(pattern)
        for pattern in (
            rf"\battempted{s}{n}s?{s}(?:was|is|were)\b",
            rf"\b{n}s?{s}(?:used|entered|tried|attempted|typed){s}(?:was|is|were)\b",
            rf"\beach{s}(?:attempt|try|logon|login|request)s?{s}(?:uses|used|tried|tries|had|has|with)"
            rf"{s}an?{s}(?:different|new|unique|distinct|separate){s}{n}\b",
            rf"\b(?:event|log|entry|record)s?{s}(?:shows?|records?|contains?|includes?|logs?|reveals?"
            rf"|captures?|lists?){s}(?:(?:the|an?){s})?(?:(?:attempted|entered|used|actual){s})?{n}s?\b"
            # "the event shows the password policy / has expired" is about the account, not a value
            rf"(?!\s*(?:(?:has|had|is|was){s})?(?:polic|expir|age\b|change|reset|histor|complexit"
            rf"|length|hash))",
            rf"\b(?:logged|recorded|captured){s}{n}s?{s}(?:was|is|were)\b",
        )
    )


def _not_recorded_rules(texts: Iterable[str], alert: Alert, kb: KnowledgeBase) -> set[str]:
    event_id = canonical_event_id(alert.event_id)
    event = None if event_id is None else kb.events.get(event_id)
    if event is None or not event.never_records:
        return set()
    # The subject of each never-records item is its last word ("the attempted <noun>").
    patterns = [p for item in event.never_records for p in _not_recorded_patterns(item.split()[-1])]
    for raw in texts:
        text = kb_text(raw)
        if any(pattern.search(text) for pattern in patterns):
            return {RULE_NOT_RECORDED}
    return set()


def scan(
    texts: Sequence[str],
    alert: Alert,
    *,
    technique: str | None = None,
    pattern: PatternFact | None = None,
    kb: KnowledgeBase | None = None,
    echo: bool = True,
) -> list[str]:
    """The check-9 rule ids for ``texts`` (the reply's strings), in ``RULES`` order.

    ``echo=False`` turns the grounded-echo exemption off (the KB self-check uses it to prove
    the table text is consistent on its own)."""
    table = load_kb() if kb is None else kb
    found = (
        _code_rules(texts, alert, table, echo)
        | _pattern_rules(technique, pattern, table)
        | _not_recorded_rules(texts, alert, table)
    )
    return [rule for rule in RULES if rule in found]


def check(ctx: Context) -> list[str]:
    return scan(
        ctx.view.strings, ctx.alert, technique=ctx.view.mitre_technique, pattern=ctx.pattern
    )
