from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import pytest
from pydantic import ValidationError

from ai_security_assistant.models import Alert, parse_ip, untrusted_fields

EXPECTED_UNTRUSTED = (
    "id",
    "rule_id",
    "severity_raw",
    "rule_name",
    "host",
    "user",
    "src_ip_raw",
    "dst_ip_raw",
    "process",
    "command_line",
    "url",
    "user_agent",
    "message",
)


def make(**overrides: Any) -> Alert:
    fields: dict[str, Any] = {
        "source": "wazuh",
        "id": "a-1",
        "timestamp": datetime(2026, 8, 10, 9, 0, tzinfo=UTC),
        "rule_id": "5760",
        "severity_raw": "5",
    }
    fields.update(overrides)
    return Alert(**fields)


def test_untrusted_marker_lists_exactly_the_expected_fields() -> None:
    assert untrusted_fields() == EXPECTED_UNTRUSTED


def test_trusted_fields_are_not_marked() -> None:
    trusted = set(Alert.model_fields) - set(untrusted_fields())
    assert trusted == {"source", "timestamp", "src_ip", "dst_ip"}


def test_valid_ip_is_parsed_and_raw_is_kept() -> None:
    alert = make(src_ip_raw="192.0.2.1", dst_ip_raw="2001:db8::1")
    assert alert.src_ip == IPv4Address("192.0.2.1")
    assert alert.dst_ip == IPv6Address("2001:db8::1")
    assert alert.src_ip_raw == "192.0.2.1"


@pytest.mark.parametrize(
    "raw", ["not-an-ip", "999.1.1.1", " 192.0.2.1", "192.0.2.1\x00", "x" * 5000]
)
def test_invalid_ip_keeps_the_alert_and_the_raw_string(raw: str) -> None:
    alert = make(src_ip_raw=raw)
    assert alert.src_ip is None
    assert alert.src_ip_raw == raw


def test_parsed_ip_is_derived_never_taken_from_input() -> None:
    alert = make(src_ip_raw="not-an-ip", src_ip=IPv4Address("203.0.113.9"))
    assert alert.src_ip is None


def test_parse_ip_rejects_non_strings() -> None:
    assert parse_ip(None) is None
    assert parse_ip(12345) is None


def test_timestamp_is_normalized_to_utc() -> None:
    local = datetime(2026, 8, 10, 11, 0, tzinfo=timezone(timedelta(hours=2)))
    alert = make(timestamp=local)
    assert alert.timestamp == datetime(2026, 8, 10, 9, 0, tzinfo=UTC)
    assert alert.timestamp.utcoffset() == timedelta(0)


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make(timestamp=datetime(2026, 8, 10, 9, 0))


def test_model_is_strict_and_closed() -> None:
    with pytest.raises(ValidationError):
        make(id=123)
    with pytest.raises(ValidationError):
        make(unknown_field="x")
    with pytest.raises(ValidationError):
        make(source="other")
    with pytest.raises(ValidationError):
        make(id="")


def test_model_is_frozen() -> None:
    alert = make()
    with pytest.raises(ValidationError):
        alert.host = "other"


def test_model_rejects_non_mapping_input() -> None:
    with pytest.raises(ValidationError):
        Alert.model_validate("not a mapping")
