"""Shared ingest machinery: hard limits, safe JSON loading, field readers, detection (TB1).

Everything here treats the input file as hostile. The limits are HARD: a file over a limit is
rejected with an ``IngestError`` (exit code 2). Truncation is Phase 3's job, not ingest's.

Error messages never echo raw input. A value that has to be named goes through ``safe_repr``,
which escapes every non-ASCII and control character, so an alert cannot write to the terminal
through an error message.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from ai_security_assistant.models import Alert

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_FIELD_CHARS = 16_384
MAX_TIMESTAMP_CHARS = 64


class IngestError(Exception):
    """Input cannot be ingested. The CLI turns it into exit code 2."""


def safe_repr(value: object, limit: int = 60) -> str:
    """ASCII-only, length-capped repr for error messages."""
    text = ascii(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


class Adapter(Protocol):
    """One input format."""

    name: str

    def matches(self, records: Sequence[object]) -> bool:
        """True when every record has this format's shape. Never raises."""

    def parse(self, records: Sequence[object]) -> list[Alert]:
        """Map records to alerts. Raises ``IngestError`` on anything malformed."""


def read_text(path: Path) -> str:
    """Read ``path`` as UTF-8, refusing anything over ``MAX_FILE_BYTES``."""
    try:
        with path.open("rb") as handle:
            # Read one byte past the limit: a file that grows or lies about its size still stops.
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise IngestError(f"cannot read {safe_repr(str(path))}: {exc.__class__.__name__}") from None
    if len(data) > MAX_FILE_BYTES:
        raise IngestError(f"input file is larger than the {MAX_FILE_BYTES} byte limit")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise IngestError("input file is not valid UTF-8") from None


def _reject_constant(name: str) -> object:
    raise ValueError(f"{name} is not allowed in JSON input")


def loads_strict(text: str) -> object:
    """``json.loads`` that rejects NaN/Infinity; nesting that is too deep is an input error."""
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except RecursionError:
        raise IngestError("JSON nesting is too deep") from None
    except json.JSONDecodeError as exc:
        raise IngestError(f"invalid JSON at line {exc.lineno} column {exc.colno}") from None
    except ValueError as exc:
        # NaN/Infinity (our own message) or an integer too large to convert.
        reason = "NaN/Infinity is not allowed" if "not allowed" in str(exc) else "invalid number"
        raise IngestError(f"invalid JSON: {reason}") from None


def parse_json_records(text: str) -> list[object]:
    """The records in ``text``: one JSON document, or JSONL (one document per non-blank line).

    A document that is a JSON array yields its items; any other document yields itself.
    """
    if not text.strip():
        raise IngestError("input file is empty")
    try:
        document = loads_strict(text)
    except IngestError as document_error:
        # Split on "\n" only: str.splitlines() also splits on U+2028, U+0085 and others, which
        # may legally appear raw inside a JSON string.
        lines = [line for line in text.split("\n") if line.strip()]
        if len(lines) < 2:
            raise
        records: list[object] = []
        for number, line in enumerate(lines, start=1):
            if len(records) >= MAX_RECORDS:
                raise IngestError(f"more than {MAX_RECORDS} records") from None
            try:
                records.append(loads_strict(line))
            except IngestError as line_error:
                raise IngestError(
                    f"input is neither one JSON document ({document_error}) "
                    f"nor JSONL (line {number}: {line_error})"
                ) from None
        return records
    return list(document) if isinstance(document, list) else [document]


def check_record_count(count: int) -> None:
    if count > MAX_RECORDS:
        raise IngestError(f"{count} records exceed the limit of {MAX_RECORDS}")


def detect_format(records: Sequence[object], adapters: Sequence[Adapter]) -> Adapter:
    """The one adapter whose shape every record has. Zero or several matches is an error."""
    if not records:
        raise IngestError("no records found in input")
    found = [adapter for adapter in adapters if adapter.matches(records)]
    if len(found) == 1:
        return found[0]
    names = ", ".join(adapter.name for adapter in adapters)
    if not found:
        raise IngestError(f"cannot detect the input format; pass --format ({names})")
    matched = ", ".join(adapter.name for adapter in found)
    raise IngestError(f"input format is ambiguous (matches {matched}); pass --format")


# --- field readers -------------------------------------------------------------------------


class Reader:
    """Typed access to one record. Wrong types and over-long strings raise ``IngestError``."""

    def __init__(self, data: object, label: str) -> None:
        if not isinstance(data, dict):
            raise IngestError(f"{label}: expected a JSON object")
        self._data: dict[str, Any] = data
        self._label = label

    def _dig(self, path: Sequence[str]) -> object:
        node: object = self._data
        for key in path:
            if not isinstance(node, dict):
                return None
            node = node.get(key)
        return node

    def obj(self, *path: str) -> dict[str, Any] | None:
        value = self._dig(path)
        if value is None:
            return None
        if not isinstance(value, dict):
            raise IngestError(f"{self._label}: field {'.'.join(path)!r} must be an object")
        return value

    def array(self, *path: str) -> list[Any]:
        value = self._dig(path)
        if not isinstance(value, list):
            raise IngestError(f"{self._label}: field {'.'.join(path)!r} must be an array")
        return value

    def text(self, *path: str, required: bool = False) -> str | None:
        """A string field. ``None`` or an empty string counts as absent."""
        name = ".".join(path)
        value = self._dig(path)
        if value is None or value == "":
            if required:
                raise IngestError(f"{self._label}: missing required field {name!r}")
            return None
        if not isinstance(value, str):
            raise IngestError(f"{self._label}: field {name!r} must be a string")
        if len(value) > MAX_FIELD_CHARS:
            raise IngestError(
                f"{self._label}: field {name!r} is longer than {MAX_FIELD_CHARS} characters"
            )
        return value

    def required(self, *path: str) -> str:
        value = self.text(*path, required=True)
        assert value is not None
        return value

    def level(self, *path: str) -> str:
        """A severity written as a string or as an integer (never a bool or a float)."""
        name = ".".join(path)
        value = self._dig(path)
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        if isinstance(value, str) and value:
            if len(value) > MAX_FIELD_CHARS:
                raise IngestError(f"{self._label}: field {name!r} is too long")
            return value
        raise IngestError(f"{self._label}: field {name!r} must be a string or an integer")

    def timestamp(self, *path: str) -> datetime:
        return parse_timestamp(self.required(*path), self._label, ".".join(path))


def parse_timestamp(text: str, label: str, name: str) -> datetime:
    """ISO 8601 with an explicit UTC offset, normalized to UTC. A naive time is rejected."""
    if len(text) > MAX_TIMESTAMP_CHARS:
        raise IngestError(f"{label}: field {name!r} is not a valid timestamp")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise IngestError(f"{label}: field {name!r} is not a valid ISO 8601 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IngestError(f"{label}: field {name!r} has no UTC offset")
    return parsed.astimezone(UTC)


def build_alert(label: str, **fields: Any) -> Alert:
    """Construct an ``Alert``; a validation failure names the fields but never echoes values."""
    try:
        return Alert(**fields)
    except ValidationError as exc:
        names = sorted({".".join(str(part) for part in err["loc"]) for err in exc.errors()})
        raise IngestError(f"{label}: invalid field(s): {', '.join(names)}") from None
