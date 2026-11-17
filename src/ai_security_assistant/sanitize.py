"""Input sanitizer (D7): the first of the input-side defenses.

It works on exactly the fields the ``Alert`` model marks untrusted (``untrusted_fields()``);
there is no second list. For each such string it:

* applies NFKC, so compatibility forms (full-width letters, ligatures, ...) fold to plain text;
* strips every character of Unicode category ``Cc`` (C0/C1 controls, DEL), ``Cf`` (zero-width
  characters, bidi overrides and isolates, soft hyphen, the tag block) and ``Cs`` (lone
  surrogates, which cannot be encoded as UTF-8);
* turns each run of line and tab separators (CR, LF, TAB, VT, FF, NEL, U+2028, U+2029) into ONE
  space. This is a decision, not an accident: a newline is the cheapest way to start a forged
  "system:" line inside a one-line field, and the model gets JSON anyway (D8), so line structure
  carries no information worth keeping. Other characters are never rewritten;
* caps the length per field and ends a truncated value with ``TRUNCATION_MARKER``;
* FLAGS (never decodes, D7) long base64 or hex runs and ``\\xNN`` escape runs;
* FLAGS tokens that mix Latin with Cyrillic or Greek letters (a homoglyph signal). Plain
  Cyrillic or Uzbek text is not a signal by itself.

Nothing is stripped silently: the report says how many characters were removed and which flags
fired, per field, but never contains the removed text (it is attacker-controlled).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Final

from ai_security_assistant.models import Alert, untrusted_fields

TRUNCATION_MARKER: Final = "[TRUNCATED]"
DEFAULT_FIELD_CAP: Final = 512

# Per-field caps in characters, keyed by the field names ``untrusted_fields()`` returns. A field
# that is missing here (a future model field) gets ``DEFAULT_FIELD_CAP``, so adding a field to
# the model can never leave it uncapped.
FIELD_CAPS: Final[Mapping[str, int]] = {
    "id": 128,
    "rule_id": 128,
    "severity_raw": 64,
    "rule_name": 256,
    "host": 255,
    "user": 128,
    "src_ip_raw": 64,
    "dst_ip_raw": 64,
    "process": 260,
    "command_line": 2048,
    "url": 2048,
    "user_agent": 512,
    "message": 2048,
}

# Work bound for a single field before normalization (NFKC can expand a character, up to 18x).
MAX_RAW_CHARS: Final = 65_536

BASE64_MIN_RUN: Final = 40
HEX_MIN_RUN: Final = 32
# Lengths of real digests (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512). A hex run of exactly
# one of these lengths is an ordinary file hash, which alerts carry all the time, not a blob.
HASH_HEX_LENGTHS: Final = frozenset({32, 40, 56, 64, 96, 128})

_SEPARATORS: Final = frozenset("\r\n\t\x0b\x0c\x85  ")
_STRIPPED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs"})
_BIDI_CONTROLS: Final = frozenset("؜‎‏‪‫‬‭‮⁦⁧⁨⁩")

_RUN_RE: Final = re.compile(r"[A-Za-z0-9+/_=-]+")
_ESCAPED_HEX_RE: Final = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,256}")
_WORD_RE: Final = re.compile(r"[^\W\d_]+")
_HEX_DIGITS: Final = frozenset("0123456789abcdefABCDEF")

# Scripts whose letters get confused with each other. Other scripts mixed into a word are not
# treated as a homoglyph signal (Uzbek Latin uses modifier letters, CJK mixes freely).
_CONFUSABLE_SCRIPTS: Final = frozenset({"LATIN", "CYRILLIC", "GREEK"})

# Cyrillic and Greek letters that look like a Latin letter. Used to build a "skeleton" for
# matching (detector) and for canary comparison; never written back into the alert.
_CONFUSABLES: Final[Mapping[str, str]] = {
    **dict(
        zip(
            "авекмнорстухіјѕһԁԛԝ",
            "abekmhopctyxijshdqw",
            strict=True,
        )
    ),
    **dict(
        zip(
            "АВЕКМНОРСТХУІЈЅ",
            "ABEKMHOPCTXYIJS",
            strict=True,
        )
    ),
    **dict(zip("αβεικνορτυχ", "abeiknoptux", strict=True)),
    **dict(zip("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "ABEZHIKMNOPTYX", strict=True)),
}


@dataclass(frozen=True)
class FieldReport:
    """What the sanitizer did to one field. Counts only, never the removed text."""

    original_length: int
    final_length: int
    controls_removed: int = 0
    bidi_controls_removed: int = 0
    separators_replaced: int = 0
    truncated: bool = False
    encoded_blobs: int = 0
    mixed_script_tokens: int = 0

    @property
    def flags(self) -> tuple[str, ...]:
        names = (
            ("controls_removed", self.controls_removed > 0),
            ("bidi_controls", self.bidi_controls_removed > 0),
            ("whitespace_normalized", self.separators_replaced > 0),
            ("truncated", self.truncated),
            ("encoded_blob", self.encoded_blobs > 0),
            ("mixed_script", self.mixed_script_tokens > 0),
        )
        return tuple(name for name, fired in names if fired)

    def to_dict(self) -> dict[str, object]:
        return {
            "flags": list(self.flags),
            "counts": {
                "original_length": self.original_length,
                "final_length": self.final_length,
                "controls_removed": self.controls_removed,
                "bidi_controls_removed": self.bidi_controls_removed,
                "separators_replaced": self.separators_replaced,
                "encoded_blobs": self.encoded_blobs,
                "mixed_script_tokens": self.mixed_script_tokens,
            },
        }


@dataclass(frozen=True)
class SanitizeReport:
    """Per-field reports for every field that held a value."""

    fields: dict[str, FieldReport] = field(default_factory=dict)

    def flagged(self) -> dict[str, tuple[str, ...]]:
        """Field name to its flags, only for fields where something fired."""
        return {name: rep.flags for name, rep in self.fields.items() if rep.flags}

    def totals(self) -> dict[str, int]:
        reports = self.fields.values()
        return {
            "fields_seen": len(self.fields),
            "fields_flagged": sum(1 for rep in reports if rep.flags),
            "controls_removed": sum(rep.controls_removed for rep in reports),
            "bidi_controls_removed": sum(rep.bidi_controls_removed for rep in reports),
            "separators_replaced": sum(rep.separators_replaced for rep in reports),
            "truncated_fields": sum(1 for rep in reports if rep.truncated),
            "encoded_blobs": sum(rep.encoded_blobs for rep in reports),
            "mixed_script_tokens": sum(rep.mixed_script_tokens for rep in reports),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "fields": {name: rep.to_dict() for name, rep in self.fields.items()},
            "totals": self.totals(),
        }


@dataclass(frozen=True)
class SanitizedAlert:
    """The trusted metadata plus every untrusted field after sanitizing (model order)."""

    source: str
    timestamp: datetime
    fields: dict[str, str | None]


# --- normalization ------------------------------------------------------------------------


@dataclass(frozen=True)
class _Normalized:
    text: str
    controls: int
    bidi: int
    separators: int


def _normalize_pass(text: str) -> tuple[str, int, int, int]:
    folded = unicodedata.normalize("NFKC", text)
    out: list[str] = []
    controls = bidi = separators = 0
    in_run = False
    for ch in folded:
        if ch in _SEPARATORS:
            if not in_run:
                out.append(" ")
                separators += 1
            in_run = True
            continue
        if unicodedata.category(ch) in _STRIPPED_CATEGORIES:
            controls += 1
            if ch in _BIDI_CONTROLS:
                bidi += 1
            # A removed character does not end a separator run: "\n<ZWSP>\n" is one space.
            continue
        in_run = False
        out.append(ch)
    return "".join(out), controls, bidi, separators


def _normalize(text: str) -> _Normalized:
    """NFKC + strip + separators, repeated until nothing changes.

    One pass is not enough: removing a zero-width joiner between a base letter and a combining
    mark makes them compose under NFKC, so the result of a single pass can still be unstable.
    The loop ends after at most two passes (composition only shortens, and never creates a
    control character).
    """
    if text.isascii() and text.isprintable():
        return _Normalized(text, 0, 0, 0)
    controls = bidi = separators = 0
    while True:
        new, c, b, s = _normalize_pass(text)
        controls, bidi, separators = controls + c, bidi + b, separators + s
        if new == text:
            return _Normalized(text, controls, bidi, separators)
        text = new


def normalize_text(text: str) -> str:
    """The sanitizer's normalization alone (no cap, no flags). Idempotent."""
    return _normalize(text[:MAX_RAW_CHARS]).text


# --- flags --------------------------------------------------------------------------------


def count_encoded_blobs(text: str) -> int:
    """Number of base64-like, hex-like and ``\\xNN`` runs. Nothing is decoded (D7)."""
    count = len(_ESCAPED_HEX_RE.findall(text))
    for match in _RUN_RE.finditer(text):
        run = match.group().rstrip("=")
        if len(run) >= HEX_MIN_RUN and all(ch in _HEX_DIGITS for ch in run):
            if len(run) not in HASH_HEX_LENGTHS:
                count += 1
        elif len(run) >= BASE64_MIN_RUN and _looks_like_base64(run):
            count += 1
    return count


def _looks_like_base64(run: str) -> bool:
    separators = run.count("-") + run.count("_")
    return (
        any(ch.isupper() for ch in run)
        and any(ch.islower() for ch in run)
        and any(ch.isdigit() for ch in run)
        # Hyphenated host and file names are not base64: real base64 has few "-" and "_".
        and separators * 8 <= len(run)
    )


@lru_cache(maxsize=4096)
def _script(ch: str) -> str:
    return unicodedata.name(ch, "").split(" ", 1)[0]


def _token_scripts(token: str) -> set[str]:
    return {_script(ch) for ch in token} & _CONFUSABLE_SCRIPTS


def count_mixed_script_tokens(text: str) -> int:
    """Words that mix Latin with Cyrillic or Greek letters. Pure Cyrillic words do not count."""
    return sum(
        1
        for match in _WORD_RE.finditer(text)
        if not match.group().isascii() and len(_token_scripts(match.group())) > 1
    )


def homoglyph_skeleton(text: str) -> str:
    """``text`` with Cyrillic/Greek lookalikes folded to Latin inside mixed-script words only.

    Plain Russian or Uzbek words are returned untouched, so a non-English rule can still match
    them. Used for matching, never written back into an alert.
    """

    def fold(match: re.Match[str]) -> str:
        token = match.group()
        if token.isascii() or len(_token_scripts(token)) < 2:
            return token
        return "".join(_CONFUSABLES.get(ch, ch) for ch in token)

    return _WORD_RE.sub(fold, text)


def fold_confusables(text: str) -> str:
    """Fold every Cyrillic/Greek lookalike to Latin, in any word. For ASCII-only needles."""
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text)


# --- public API ---------------------------------------------------------------------------


def sanitize_text(text: str, cap: int = DEFAULT_FIELD_CAP) -> tuple[str, FieldReport]:
    """Sanitize one string. The result is at most ``cap`` characters, NFKC-stable and clean."""
    if cap <= len(TRUNCATION_MARKER):
        raise ValueError("cap must be larger than the truncation marker")
    original_length = len(text)
    pre_truncated = original_length > MAX_RAW_CHARS
    norm = _normalize(text[:MAX_RAW_CHARS])
    cleaned = norm.text
    # Flags look at the whole normalized value, also at the part the cap is about to cut off.
    blobs = count_encoded_blobs(cleaned)
    mixed = count_mixed_script_tokens(cleaned)
    truncated = pre_truncated or len(cleaned) > cap
    if truncated:
        # Cut so that kept text + marker fits the cap (and the work bound), whichever is smaller.
        keep = max(0, min(cap, len(cleaned)) - len(TRUNCATION_MARKER))
        cleaned = _normalize(cleaned[:keep] + TRUNCATION_MARKER).text
    return cleaned, FieldReport(
        original_length=original_length,
        final_length=len(cleaned),
        controls_removed=norm.controls,
        bidi_controls_removed=norm.bidi,
        separators_replaced=norm.separators,
        truncated=truncated,
        encoded_blobs=blobs,
        mixed_script_tokens=mixed,
    )


def sanitize_alert(
    alert: Alert, caps: Mapping[str, int] | None = None
) -> tuple[SanitizedAlert, SanitizeReport]:
    """Sanitize every field the model marks untrusted. ``None`` stays ``None``."""
    limits = FIELD_CAPS if caps is None else caps
    values: dict[str, str | None] = {}
    reports: dict[str, FieldReport] = {}
    for name in untrusted_fields():
        raw = getattr(alert, name)
        if raw is None:
            values[name] = None
            continue
        text, report = sanitize_text(raw, limits.get(name, DEFAULT_FIELD_CAP))
        values[name] = text
        reports[name] = report
    return (
        SanitizedAlert(source=alert.source, timestamp=alert.timestamp, fields=values),
        SanitizeReport(fields=reports),
    )
