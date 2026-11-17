"""Check 8 (severity floor, D33): the model may raise severity, never lower it below the source's.

The floor comes ONLY from a strict table per source, applied to the alert's raw severity exactly
as the source wrote it:

* mini-siem: its ``Severity`` enum, exact lowercase (``info`` ... ``critical``);
* soc-log-analyzer: its ``Severity`` enum, exact uppercase (``LOW`` ... ``CRITICAL``);
* Wazuh: ``rule.level`` as a plain integer 0-15, in the bands 0-3 info, 4-6 low, 7-11 medium,
  12-14 high, 15 critical.

Nothing is parsed out of free text: no case folding, no trimming, no word lists. Any other raw
value (another case, padding, a sign, leading zeros, a level above 15, an unknown word) is
unmappable and gives NO floor, so the alert is judged by the other checks only.

A higher severity than the floor is accepted by design (D33): an injected "mark this critical"
costs analyst attention but hides nothing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

from ai_security_assistant.schema import Severity
from ai_security_assistant.validator.schema import Context

RULE_DOWNGRADE: Final = "downgrade"

RANK: Final[Mapping[Severity, int]] = {severity: rank for rank, severity in enumerate(Severity)}
_VALUES: Final = frozenset(severity.value for severity in Severity)

_ENUM_FLOORS: Final[Mapping[str, Mapping[str, Severity]]] = {
    "mini-siem": {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    },
    "soc-log-analyzer": {
        "LOW": Severity.LOW,
        "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH,
        "CRITICAL": Severity.CRITICAL,
    },
}

_WAZUH_LEVEL_RE: Final = re.compile(r"0|[1-9][0-9]?")
WAZUH_MAX_LEVEL: Final = 15
# The lowest level of each band, highest band first.
_WAZUH_BANDS: Final = (
    (15, Severity.CRITICAL),
    (12, Severity.HIGH),
    (7, Severity.MEDIUM),
    (4, Severity.LOW),
    (0, Severity.INFO),
)


def _wazuh_floor(raw: str) -> Severity | None:
    if _WAZUH_LEVEL_RE.fullmatch(raw) is None:
        return None
    level = int(raw)
    if level > WAZUH_MAX_LEVEL:
        return None
    return next(severity for lowest, severity in _WAZUH_BANDS if level >= lowest)


def severity_floor(source: str, raw: str) -> Severity | None:
    """The floor for a source's raw severity, or ``None`` when it is unmappable."""
    if source == "wazuh":
        return _wazuh_floor(raw)
    table = _ENUM_FLOORS.get(source)
    return None if table is None else table.get(raw)


def check(ctx: Context) -> list[str]:
    """Check 8: an output severity below the source's floor is a downgrade."""
    floor = severity_floor(ctx.alert.source, ctx.alert.severity_raw)
    value = ctx.view.severity
    if floor is None or value is None or value not in _VALUES:
        return []  # no floor, or no enum severity to judge (check 1 reports the latter)
    return [RULE_DOWNGRADE] if RANK[Severity(value)] < RANK[floor] else []
