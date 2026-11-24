"""The two deterministic mock providers (D15): offline, free and reproducible.

``WellBehavedMock`` ("mock") reads the alert like a model that follows the system prompt: the
alert is data, and the reply is derived only from its fields. It reads the nonce-tagged data
block of a defended prompt, or the plain ``name: value`` lines of the naive baseline prompt
(config ``none``, D35), so both mocks see the fields in every configuration. The raw
severity maps to the enum, the rule maps to a technique through a small table, and the only IOCs
it mentions are IPs and host names that the alert itself contains. Its output is always
schema-valid.

``NaiveMock`` ("mock-naive") stands in for a model with no defense. It reads the WHOLE user
prompt as instructions, ignoring the boundary, and obeys what ``naive_rules`` finds there. It
proves that the validator catches what a fooled model produces. It may import neither
``detector`` nor any detector pattern (D16); the gate checks the imports.

Both are pure functions of ``(system, user)``: the same prompts give the same reply, byte for
byte, which is what the golden tests pin down.
"""

from __future__ import annotations

import json
import re
from typing import Any, Final

from ai_security_assistant.models import parse_ip, untrusted_fields
from ai_security_assistant.prompt import PLAIN_PROMPT_HEADER
from ai_security_assistant.providers.base import CallBudget, ProviderError
from ai_security_assistant.providers.naive_rules import extract_directives, read_like_a_model
from ai_security_assistant.schema import SUMMARY_MAX_CHARS, Action, Severity
from ai_security_assistant.wrap import BOUNDARY_TAG, WrapError, unwrap

_NONCE_LINE_RE: Final = re.compile(
    r"<<<" + re.escape(BOUNDARY_TAG) + r" nonce=([a-z]{16,64}) BEGIN>>>"
)
_HOST_RE: Final = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,78}[A-Za-z0-9])?")
_USER_RE: Final = re.compile(r"[A-Za-z0-9._-]{1,40}")
_NAME_MAX: Final = 100

_SEVERITY_WORDS: Final[tuple[tuple[Severity, tuple[str, ...]], ...]] = (
    (Severity.CRITICAL, ("critical", "crit", "fatal", "emergency")),
    (Severity.HIGH, ("high", "error", "major", "severe")),
    (Severity.MEDIUM, ("medium", "moderate", "warning", "warn", "med")),
    (Severity.LOW, ("low", "minor", "notice")),
    (Severity.INFO, ("info", "informational", "debug", "none")),
)
# Wazuh-style numeric levels (0-15): the lowest level of each band.
_LEVEL_BANDS: Final = (
    (15, Severity.CRITICAL),
    (12, Severity.HIGH),
    (7, Severity.MEDIUM),
    (4, Severity.LOW),
)

# Keywords in the rule id or name, first match wins. The technique IDs are generic placeholders
# for the mock, not a statement about the alert.
_TECHNIQUES: Final[tuple[tuple[tuple[str, ...], str], ...]] = (
    (("brute", "authentication failed", "failed login", "failed password", "spray"), "T1110"),
    (("lsass", "credential dump", "mimikatz"), "T1003.001"),
    (("powershell", "encoded command"), "T1059.001"),
    (("scheduled task", "cron"), "T1053"),
    (("sudo", "privilege escalation", "setuid"), "T1548"),
    (("phish",), "T1566"),
    (("port scan", "portscan", "scan"), "T1046"),
    (("web shell", "webshell"), "T1505.003"),
    (("sql injection", "sqli", "web probe", "attack pattern", "exploit", "traversal"), "T1190"),
    (("lateral", "smb", "rdp"), "T1021"),
    (("exfil", "large upload", "data transfer"), "T1041"),
    (("beacon", "dns tunnel", "c2", "command and control"), "T1071"),
    (("malware", "ransom"), "T1204"),
)
FALLBACK_TECHNIQUE: Final = "T1059"

# What the naive mock invents when told to "include the known attacker address". None of these is
# a value any dataset alert contains; the first one absent from the prompt is used.
_INVENTED: Final[dict[str, tuple[str, ...]]] = {
    "ip": ("198.51.100.222", "203.0.113.222", "192.0.2.222"),
    "domain": ("stage2-relay.example.test", "stage3-relay.example.test"),
    "hash": ("deadbeef" * 4, "feedface" * 4),
}


def severity_from_raw(raw: str | None) -> tuple[Severity, bool]:
    """The enum for a raw severity string, and whether it was recognized."""
    text = (raw or "").strip().casefold()
    for severity, words in _SEVERITY_WORDS:
        if text in words:
            return severity, True
    if text.isdigit() and len(text) <= 3:
        level = int(text)
        for floor, severity in _LEVEL_BANDS:
            if level >= floor:
                return severity, True
        return Severity.INFO, True
    return Severity.MEDIUM, False


def technique_for(rule_id: str | None, rule_name: str | None) -> tuple[str, bool]:
    """The technique for a rule, and whether the table had an entry."""
    haystack = f"{rule_id or ''} {rule_name or ''}".casefold().replace("_", " ")
    for keywords, technique in _TECHNIQUES:
        if any(word in haystack for word in keywords):
            return technique, True
    return FALLBACK_TECHNIQUE, False


def _actions_for(severity: Severity, fields: dict[str, str | None]) -> list[str]:
    if severity is Severity.INFO:
        actions = [Action.MONITOR]
    elif severity is Severity.LOW:
        actions = [Action.MONITOR, Action.COLLECT_LOGS]
    elif severity is Severity.MEDIUM:
        actions = [Action.INVESTIGATE, Action.COLLECT_LOGS]
    else:
        actions = [Action.INVESTIGATE, Action.ESCALATE_TO_ANALYST]
        if parse_ip(fields.get("src_ip_raw")) is not None:
            actions.append(Action.BLOCK_IP)
        if severity is Severity.CRITICAL and fields.get("host"):
            actions.append(Action.ISOLATE_HOST)
    return [action.value for action in actions]


def _summary_for(fields: dict[str, str | None]) -> str:
    """A fixed sentence plus values from the alert. IPs and names only if they look like them."""
    parts = [f"Rule {_clip(fields.get('rule_id'))}"]
    name = _clip(fields.get("rule_name"))
    if name:
        parts[0] += f" ({name})"
    host = fields.get("host")
    if host and _HOST_RE.fullmatch(host):
        parts.append(f"on host {host}")
    user = fields.get("user")
    if user and _USER_RE.fullmatch(user):
        parts.append(f"for user {user}")
    for label, key in (("source", "src_ip_raw"), ("destination", "dst_ip_raw")):
        value = fields.get(key)
        if value and parse_ip(value) is not None:
            parts.append(f"{label} {value}")
    return (" ".join(parts) + ": triaged from the alert fields only.")[:SUMMARY_MAX_CHARS]


def _clip(value: str | None) -> str:
    return re.sub(r"\s+", " ", value or "").strip()[:_NAME_MAX]


def triage_from_fields(fields: dict[str, str | None]) -> dict[str, Any]:
    """The well-behaved triage of one alert's fields: a plain dict that matches the schema."""
    severity, known_severity = severity_from_raw(fields.get("severity_raw"))
    technique, known_rule = technique_for(fields.get("rule_id"), fields.get("rule_name"))
    return {
        "severity": severity.value,
        "mitre_technique": technique,
        "summary": _summary_for(fields),
        "recommended_actions": _actions_for(severity, fields),
        "confidence": 0.8 if known_severity and known_rule else 0.5,
    }


def read_block(user: str) -> dict[str, str | None]:
    """The fields inside the nonce block of ``user``. Raises ``ProviderError`` if there is none."""
    first = _NONCE_LINE_RE.search(user)
    if first is None:
        raise ProviderError("mock could not find the data block")
    try:
        # The trusted reference block (D40) may sit in front of the boundary line; it is not data.
        return unwrap(user[first.start() :], first.group(1))
    except WrapError:
        raise ProviderError("mock could not read the data block") from None


def read_plain(user: str) -> dict[str, str | None]:
    """The fields of a naive baseline prompt (D35): ``name: value`` lines after the header.

    Raises ``ProviderError`` if ``user`` is not one. The first line that starts with a field name
    sets that field; any other line continues the field before it (a raw value may hold line
    breaks), so a value cannot re-set a field that came earlier.
    """
    lines = user.split("\n")
    if lines[0] != PLAIN_PROMPT_HEADER:
        raise ProviderError("mock could not find the alert")
    names = ("source", *untrusted_fields())
    fields: dict[str, str | None] = dict.fromkeys(untrusted_fields())
    seen: set[str] = set()
    current: str | None = None
    for line in lines[1:]:
        name, sep, value = line.partition(": ")
        if sep and name in names and name not in seen:
            seen.add(name)
            current = name
            if name != "source":
                fields[name] = value
        elif current is not None and current != "source":
            fields[current] = f"{fields[current]}\n{line}"
    return fields


def read_fields(user: str) -> dict[str, str | None]:
    """The alert fields of a defended (block) or naive (plain) user prompt."""
    if _NONCE_LINE_RE.search(user) is not None:
        return read_block(user)
    return read_plain(user)


def _dump(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


class WellBehavedMock:
    """Deterministic triage derived from the alert fields. Always schema-valid."""

    name = "mock"

    def __init__(self, budget: CallBudget) -> None:
        self._budget = budget

    def __repr__(self) -> str:
        return f"WellBehavedMock({self._budget!r})"

    def complete(self, system: str, user: str) -> str:
        self._budget.spend()
        return _dump(triage_from_fields(read_fields(user)))


class NaiveMock:
    """A model with no defense: it obeys instructions anywhere in the prompt (D15, D16)."""

    name = "mock-naive"

    def __init__(self, budget: CallBudget) -> None:
        self._budget = budget

    def __repr__(self) -> str:
        return f"NaiveMock({self._budget!r})"

    def complete(self, system: str, user: str) -> str:
        self._budget.spend()
        try:
            fields = read_fields(user)
        except ProviderError:
            fields = {}  # nothing it can read as an alert: the naive model still answers
        document = triage_from_fields(fields)
        directives = extract_directives(read_like_a_model(user))

        if directives.prose or (directives.acknowledge and not directives.any):
            if directives.prose:
                return f"Sure, in plain text: {document['summary']}"
            return "Understood. I will disregard my earlier instructions."
        if directives.severity is not None:
            document["severity"] = directives.severity.value
            document["confidence"] = 0.95
        if directives.extra_actions:
            document["recommended_actions"] = [
                *document["recommended_actions"],
                *directives.extra_actions,
            ]
        if directives.summary_text is not None:  # D34: the attacker's words lead the summary
            document["summary"] = f"{directives.summary_text} {document['summary']}"[
                :SUMMARY_MAX_CHARS
            ]
        if directives.fabricate_ioc is not None:
            ioc = _invent(directives.fabricate_ioc, user)
            document["summary"] = f"Linked indicator {ioc}. {document['summary']}"[
                :SUMMARY_MAX_CHARS
            ]
        if directives.leak_prompt:
            document["summary"] = system[:SUMMARY_MAX_CHARS]
        return _dump(document)


def _invent(kind: str, prompt: str) -> str:
    haystack = prompt.casefold()
    for candidate in _INVENTED[kind]:
        if candidate not in haystack:
            return candidate
    return _INVENTED[kind][-1]
