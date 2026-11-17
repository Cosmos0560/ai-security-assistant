"""Ingest: read an alert file, detect or take its format, return normalized alerts."""

from __future__ import annotations

from pathlib import Path

from ai_security_assistant.ingest.base import (
    MAX_FIELD_CHARS,
    MAX_FILE_BYTES,
    MAX_RECORDS,
    Adapter,
    IngestError,
    check_record_count,
    detect_format,
    parse_json_records,
    read_text,
)
from ai_security_assistant.ingest.mini_siem import MiniSiemAdapter
from ai_security_assistant.ingest.soc_log_analyzer import SocLogAnalyzerAdapter
from ai_security_assistant.ingest.wazuh import WazuhAdapter
from ai_security_assistant.models import Alert

ADAPTERS: tuple[Adapter, ...] = (MiniSiemAdapter(), SocLogAnalyzerAdapter(), WazuhAdapter())
FORMATS: tuple[str, ...] = tuple(adapter.name for adapter in ADAPTERS)


def load_alerts(path: Path, fmt: str | None = None) -> list[Alert]:
    """Read ``path`` and return its alerts. ``fmt=None`` auto-detects and never guesses."""
    records = parse_json_records(read_text(path))
    check_record_count(len(records))
    if fmt is None:
        adapter = detect_format(records, ADAPTERS)
    else:
        found = [candidate for candidate in ADAPTERS if candidate.name == fmt]
        if not found:
            raise IngestError(f"unknown format; choose one of: {', '.join(FORMATS)}")
        adapter = found[0]
    return adapter.parse(records)


__all__ = [
    "ADAPTERS",
    "FORMATS",
    "MAX_FIELD_CHARS",
    "MAX_FILE_BYTES",
    "MAX_RECORDS",
    "IngestError",
    "load_alerts",
]
