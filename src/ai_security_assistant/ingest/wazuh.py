"""Wazuh-style adapter: alerts as in ``alerts.json`` (JSONL) or a JSON array of them.

Modelled on the public Wazuh alert structure: ``timestamp``, ``id``, ``rule`` (``id``,
``level``, ``description``), ``agent`` (``name``), ``predecoder``, ``data`` and ``full_log``.
``data`` follows the static decoder fields (``srcip``, ``dstip``, ``srcuser``, ``dstuser``,
``url``, ``command``) and the Suricata-style nested ``data.http`` / ``src_ip`` / ``dest_ip``.
Windows Security events (the ``eventchannel`` decoder) add ``data.win``: only
``system.eventID`` and ``eventdata.{logonType,status,subStatus,targetUserName,ipAddress}`` are
read (``ipAddress`` is a fallback source address; ``-`` means none), and every other ``win`` key is
dropped like every other key (TB1). ``rule.level`` becomes the raw severity.
"""

from __future__ import annotations

from collections.abc import Sequence

from ai_security_assistant.ingest.base import Reader, build_alert
from ai_security_assistant.models import Alert

NAME = "wazuh"


def _first(*values: str | None) -> str | None:
    return next((value for value in values if value is not None), None)


def _address(value: str | None) -> str | None:
    """A Windows source address, where ``-`` means there is none (and is then absent)."""
    return None if value == "-" else value


class WazuhAdapter:
    name = NAME

    def matches(self, records: Sequence[object]) -> bool:
        return all(
            isinstance(record, dict)
            and isinstance(record.get("rule"), dict)
            and isinstance(record.get("agent"), dict)
            for record in records
        )

    def parse(self, records: Sequence[object]) -> list[Alert]:
        return [self._one(record, number) for number, record in enumerate(records, start=1)]

    @staticmethod
    def _one(record: object, number: int) -> Alert:
        label = f"wazuh record {number}"
        alert = Reader(record, label)
        return build_alert(
            label,
            source=NAME,
            id=alert.required("id"),
            timestamp=alert.timestamp("timestamp"),
            rule_id=alert.required("rule", "id"),
            rule_name=alert.text("rule", "description"),
            severity_raw=alert.level("rule", "level"),
            host=alert.text("agent", "name"),
            user=_first(alert.text("data", "dstuser"), alert.text("data", "srcuser")),
            src_ip_raw=_first(
                alert.text("data", "srcip"),
                alert.text("data", "src_ip"),
                _address(alert.text("data", "win", "eventdata", "ipAddress")),
            ),
            dst_ip_raw=_first(alert.text("data", "dstip"), alert.text("data", "dest_ip")),
            process=_first(
                alert.text("data", "audit", "exe"), alert.text("predecoder", "program_name")
            ),
            command_line=_first(
                alert.text("data", "command"), alert.text("data", "audit", "command")
            ),
            url=_first(alert.text("data", "url"), alert.text("data", "http", "url")),
            user_agent=alert.text("data", "http", "http_user_agent"),
            message=alert.text("full_log"),
            event_id=alert.text("data", "win", "system", "eventID"),
            logon_type=alert.text("data", "win", "eventdata", "logonType"),
            status=alert.text("data", "win", "eventdata", "status"),
            sub_status=alert.text("data", "win", "eventdata", "subStatus"),
            target_user=alert.text("data", "win", "eventdata", "targetUserName"),
        )
