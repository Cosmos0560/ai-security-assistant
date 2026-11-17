"""mini-siem adapter: JSONL of ``mini-siem.alert.v1`` notices, one per line.

Each line is ``{"schema", "alert": {...}, "suppressed_since_last"}``. The alert holds a
deterministic ``alert_id``, ``rule_id``, ``title``, ``severity``, ``confidence``, ``timestamp``,
``group_key``, ``mitre``, ``event_ids``, ``summary`` and an ``entity`` map of the group-by
fields (``source_ip``, ``user_name``, ``host``). Everything else is dropped (TB1).
"""

from __future__ import annotations

from collections.abc import Sequence

from ai_security_assistant.ingest.base import IngestError, Reader, build_alert
from ai_security_assistant.models import Alert

NAME = "mini-siem"
SCHEMA = "mini-siem.alert.v1"
ALERT_SCHEMA_VERSION = "1"


class MiniSiemAdapter:
    name = NAME

    def matches(self, records: Sequence[object]) -> bool:
        return all(
            isinstance(record, dict)
            and record.get("schema") == SCHEMA
            and isinstance(record.get("alert"), dict)
            for record in records
        )

    def parse(self, records: Sequence[object]) -> list[Alert]:
        return [self._one(record, number) for number, record in enumerate(records, start=1)]

    def _one(self, record: object, number: int) -> Alert:
        label = f"mini-siem record {number}"
        outer = Reader(record, label)
        if outer.text("schema") != SCHEMA:
            raise IngestError(f"{label}: schema is not {SCHEMA!r}")
        inner = Reader(outer.obj("alert"), label)
        if inner.text("schema_version") != ALERT_SCHEMA_VERSION:
            raise IngestError(f"{label}: unsupported alert schema_version")
        entity = Reader(inner.obj("entity") or {}, label)
        return build_alert(
            label,
            source=NAME,
            id=inner.required("alert_id"),
            timestamp=inner.timestamp("timestamp"),
            rule_id=inner.required("rule_id"),
            rule_name=inner.text("title"),
            severity_raw=inner.required("severity"),
            host=entity.text("host"),
            user=entity.text("user_name"),
            src_ip_raw=entity.text("source_ip"),
            message=inner.text("summary"),
        )
