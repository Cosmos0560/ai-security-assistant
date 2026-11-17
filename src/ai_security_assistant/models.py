"""The normalized alert model (D6). Every ingest adapter produces ``Alert`` and nothing else.

Fields that carry text chosen by whoever wrote the log line (or the alert file) are marked
untrusted in the model itself, through ``Field(json_schema_extra={"untrusted": True})``.
``untrusted_fields()`` lists them, so the Phase 3 sanitizer finds them programmatically
instead of keeping a second list that can drift.

Only ``source`` (set by the adapter) and ``timestamp`` (a parsed value) are trusted. Every
other string came out of an attacker-reachable file, including ids and severities.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

UNTRUSTED_MARKER = "untrusted"

SourceName = Literal["mini-siem", "soc-log-analyzer", "wazuh"]


def _untrusted() -> Any:
    """Optional free-text field that an attacker can influence."""
    return Field(default=None, json_schema_extra={UNTRUSTED_MARKER: True})


def parse_ip(raw: object) -> IPv4Address | IPv6Address | None:
    """The parsed address, or ``None`` when ``raw`` is not a valid IP. Never raises."""
    if not isinstance(raw, str):
        return None
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


class Alert(BaseModel):
    """One normalized SOC alert."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    # Trusted: the adapter sets it from a fixed set; the timestamp is a parsed, UTC value.
    source: SourceName
    timestamp: AwareDatetime

    # Untrusted, required: identifiers and the raw severity exactly as the source wrote them.
    id: str = Field(min_length=1, json_schema_extra={UNTRUSTED_MARKER: True})
    rule_id: str = Field(min_length=1, json_schema_extra={UNTRUSTED_MARKER: True})
    severity_raw: str = Field(min_length=1, json_schema_extra={UNTRUSTED_MARKER: True})

    # Untrusted, optional.
    rule_name: str | None = _untrusted()
    host: str | None = _untrusted()
    user: str | None = _untrusted()
    # An IP field keeps the raw string (untrusted). The parsed address exists only when the
    # raw string is a valid IP; an invalid value never drops or rejects the alert.
    src_ip_raw: str | None = _untrusted()
    dst_ip_raw: str | None = _untrusted()
    process: str | None = _untrusted()
    command_line: str | None = _untrusted()
    url: str | None = _untrusted()
    user_agent: str | None = _untrusted()
    message: str | None = _untrusted()

    # Derived from the raw strings above, never taken from input.
    src_ip: IPv4Address | IPv6Address | None = None
    dst_ip: IPv4Address | IPv6Address | None = None

    @model_validator(mode="before")
    @classmethod
    def _derive_ips(cls, data: Any) -> Any:
        if isinstance(data, dict):
            data = dict(data)
            data["src_ip"] = parse_ip(data.get("src_ip_raw"))
            data["dst_ip"] = parse_ip(data.get("dst_ip_raw"))
        return data

    @field_validator("timestamp")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


def untrusted_fields() -> tuple[str, ...]:
    """Names of every field marked untrusted, in model order."""
    return tuple(
        name
        for name, info in Alert.model_fields.items()
        if isinstance(info.json_schema_extra, dict)
        and info.json_schema_extra.get(UNTRUSTED_MARKER) is True
    )
