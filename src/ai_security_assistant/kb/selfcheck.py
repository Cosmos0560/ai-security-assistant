"""KB self-consistency (D42 invariant): the table's own reference text must pass check 9.

For every entry (each status both as Status and as SubStatus), the line the trusted reference
block renders for it is used as the model's summary, on an alert whose facts hold exactly that
entry. Two readings must both pass:

* with the grounded-echo exemption (what a faithful model that quotes the block gets);
* without it (the table text names no other code and no other entry's alias, so a partial
  quote or a light paraphrase of it passes too).

The gate runs ``python -m ai_security_assistant.kb.selfcheck`` in the project venv, so the gate
itself stays stdlib-only. Exit 0 when consistent, 1 with one line per problem otherwise.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Final

from ai_security_assistant.kb import Fact, FactKind, KnowledgeBase, ReferenceFacts, load_kb
from ai_security_assistant.models import Alert
from ai_security_assistant.prompt import render_reference_block
from ai_security_assistant.validator.kb import scan

_FIELD: Final[dict[FactKind, str]] = {
    "event": "event_id",
    "logon_type": "logon_type",
    "status": "status",
    "sub_status": "sub_status",
}
# An alert with no Windows key at all; each probe sets exactly one.
_PROBE: Final = Alert(
    source="wazuh",
    timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    id="kb-self-check",
    rule_id="kb-self-check",
    severity_raw="0",
)


def _facts(kb: KnowledgeBase) -> Iterator[Fact]:
    for code, event in kb.events.items():
        yield Fact("event", code, event.name, event.meaning, event.never_records)
    for code, logon in kb.logon_types.items():
        yield Fact("logon_type", code, logon.name, logon.meaning)
    for kind in ("status", "sub_status"):
        for code, status in kb.statuses.items():
            yield Fact(kind, code, status.name, status.meaning)


def reference_line(fact: Fact, kb_version: str) -> str:
    """The line the reference block renders for ``fact`` alone, without the list marker."""
    block = render_reference_block(ReferenceFacts(kb_version, (fact,), None))
    return block.splitlines()[1].removeprefix("- ")


def problems(kb: KnowledgeBase) -> list[str]:
    found: list[str] = []
    for fact in _facts(kb):
        alert = _PROBE.model_copy(update={_FIELD[fact.kind]: fact.code})
        line = reference_line(fact, kb.kb_version)
        for echo, reading in ((True, "quoted"), (False, "as a plain claim")):
            rules = scan([line], alert, kb=kb, echo=echo)
            if rules:
                found.append(f"{fact.kind} {fact.code}: its reference text {reading} fails {rules}")
    return found


def main() -> int:
    found = problems(load_kb())
    for problem in found:
        print(problem)
    if not found:
        print("Windows KB reference text passes check 9")
    return 1 if found else 0


if __name__ == "__main__":  # pragma: no cover - the gate runs it as a module
    sys.exit(main())
