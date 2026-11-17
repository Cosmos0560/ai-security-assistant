"""Check 7: secret scan of the reply with the vendored secret-scanner v1.0.0 (D12, D19, T7).

Every string of the permissive view AND the raw text are scanned, so a secret hidden behind a
JSON escape (``\\u0041``) is found in the decoded string, and one in an extra key or in prose is
found in the raw text. The reason is the scanner's rule id (a fixed, vendored value), never the
matched text.

The scanner runs its regex rules and its private-key detector. Its entropy detector is OFF: a
grounded sha256 or md5 in a summary is a legitimate indicator, and the entropy detector would
flag every one. NUL characters are removed before scanning (the scanner treats a buffer with a
NUL as binary and skips it). Content the scanner cannot read in full (a binary buffer or a cut
line) fails closed as ``unscannable``.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Iterable
from importlib import resources
from typing import Final

from ai_security_assistant.third_party.secret_scanner.core.detect.engine import Engine
from ai_security_assistant.third_party.secret_scanner.core.detect.entropy import EntropyConfig
from ai_security_assistant.third_party.secret_scanner.core.lines import TextKind
from ai_security_assistant.third_party.secret_scanner.core.models import Rule
from ai_security_assistant.third_party.secret_scanner.core.rules import parse_rules_document
from ai_security_assistant.validator.schema import MAX_ANALYSIS_CHARS, Context

SCANNER_PACKAGE: Final = "ai_security_assistant.third_party.secret_scanner"
RULES_PATH: Final = ("rules", "builtin.json")
RULE_UNSCANNABLE: Final = "unscannable"


@functools.cache
def builtin_rules() -> tuple[Rule, ...]:
    """The vendored built-in rules, validated by the vendored rules parser."""
    resource = resources.files(SCANNER_PACKAGE).joinpath(*RULES_PATH)
    return parse_rules_document(json.loads(resource.read_text(encoding="utf-8")))


@functools.cache
def engine() -> Engine:
    return Engine(builtin_rules(), entropy=EntropyConfig(enabled=False))


def scan_texts(texts: Iterable[str]) -> list[str]:
    """Sorted, unique rule ids found in ``texts`` (plus ``unscannable`` if one was not read)."""
    found: set[str] = set()
    scanner = engine()
    for text in texts:
        data = text.replace("\0", "").encode("utf-8", "replace")
        result = scanner.scan(data, use_entropy=False)
        if result.kind is not TextKind.TEXT or result.long_lines:
            found.add(RULE_UNSCANNABLE)
        found.update(match.rule_id for match in result.matches)
    return sorted(found)


def check(ctx: Context) -> list[str]:
    texts = list(ctx.view.strings)
    if ctx.result.raw_text is not None:
        texts.append(ctx.result.raw_text[:MAX_ANALYSIS_CHARS])
    return scan_texts(texts)
