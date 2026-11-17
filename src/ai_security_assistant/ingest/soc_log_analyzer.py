"""soc-log-analyzer adapter: the ``--json`` document, schema_version 1.x (docs/OUTPUT_SCHEMA.md).

Two document kinds are supported: ``analysis`` and ``stored_alerts``. ``alerts[]`` maps to
``Alert``; sources, summary, counts and every ``details`` key except ``path`` are dropped (TB1).
The contract says ``source_ip`` is whatever ``\\S+`` matched, so it is kept as a raw string, and
``username``, ``details.path`` and the other log-derived values are treated as untrusted.
A major version other than 1 is refused rather than guessed at.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ai_security_assistant.ingest.base import (
    IngestError,
    Reader,
    build_alert,
    check_record_count,
    safe_repr,
)
from ai_security_assistant.models import Alert

NAME = "soc-log-analyzer"
KINDS = ("analysis", "stored_alerts")
_VERSION = re.compile(r"(\d{1,6})\.(\d{1,6})")


class SocLogAnalyzerAdapter:
    name = NAME

    def matches(self, records: Sequence[object]) -> bool:
        if len(records) != 1:
            return False
        document = records[0]
        return (
            isinstance(document, dict)
            and {"schema_version", "kind", "alerts"} <= document.keys()
            and isinstance(document["alerts"], list)
        )

    def parse(self, records: Sequence[object]) -> list[Alert]:
        if len(records) != 1:
            raise IngestError("soc-log-analyzer input must be exactly one JSON document")
        document = Reader(records[0], "soc-log-analyzer document")
        self._check_version(document.required("schema_version"))
        kind = document.required("kind")
        if kind not in KINDS:
            raise IngestError(f"unsupported soc-log-analyzer kind {safe_repr(kind)}")
        raw_alerts = document.array("alerts")
        check_record_count(len(raw_alerts))
        return [self._one(raw, number, kind) for number, raw in enumerate(raw_alerts, start=1)]

    @staticmethod
    def _check_version(version: str) -> None:
        found = _VERSION.fullmatch(version)
        if found is None:
            raise IngestError(f"invalid soc-log-analyzer schema_version {safe_repr(version)}")
        if found.group(1) != "1":
            raise IngestError(
                f"unsupported soc-log-analyzer schema_version {safe_repr(version)}: "
                "only major version 1 is supported"
            )

    @staticmethod
    def _one(raw: object, number: int, kind: str) -> Alert:
        label = f"soc-log-analyzer alert {number}"
        alert = Reader(raw, label)
        alert_type = alert.required("alert_type")
        stored_id = alert.level("id") if kind == "stored_alerts" else None
        return build_alert(
            label,
            source=NAME,
            id=f"stored-{stored_id}" if stored_id is not None else f"analysis-{number}",
            timestamp=alert.timestamp("timestamp"),
            rule_id=alert_type,
            rule_name=alert_type,
            severity_raw=alert.required("severity"),
            user=alert.text("username"),
            src_ip_raw=alert.text("source_ip"),
            url=alert.text("details", "path"),
            message=alert.text("description"),
        )
