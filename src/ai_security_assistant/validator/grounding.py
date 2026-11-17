"""Check 4: IOC grounding. Every indicator in the output must appear in the alert (D12, T5).

Indicators are IPv4 and IPv6 addresses, domains, URLs and md5/sha1/sha256 hashes. They are taken
from EVERY string of the reply (keys included; the raw text when the reply is not JSON) and from
every string field of the ORIGINAL alert, with the same extractor on both sides, after the same
normalization:

* the sanitizer's normalization (NFKC, zero-width and bidi characters removed), then case
  folding, so hash and domain case never matter;
* defanged forms are refanged: ``hxxp`` -> ``http``, ``[.]`` ``(.)`` ``{.}`` ``[dot]`` ``(dot)``
  -> ``.``, ``[:]`` -> ``:``, ``[://]`` -> ``://``;
* IPv4 octets lose leading zeros; IPv6 is compared in its compressed form.

A domain in the alert also grounds its parent domains (``a.example.test`` grounds
``example.test``). Lookalike letters are NOT folded: a domain spelled with a Cyrillic letter is a
different domain, and it is ungrounded unless the alert has exactly that spelling.

Residual risk (T5), by design: an indicator the ATTACKER planted in the alert is grounded,
because grounding only proves the model did not invent it. A planted indicator in an accepted
report is still attacker-chosen; the human reviewer decides what to block (D13).

A suffix that is a common file extension and not a delegated top-level domain (``exe``, ``dll``,
``ps1`` ...) does not make a domain, so ``powershell.exe`` is a file name, not an indicator.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address
from typing import Final

from ai_security_assistant.models import Alert
from ai_security_assistant.sanitize import normalize_text
from ai_security_assistant.validator.schema import Context

IPV4: Final = "ipv4"
IPV6: Final = "ipv6"
DOMAIN: Final = "domain"
URL: Final = "url"
HASH: Final = "hash"
KINDS: Final = (IPV4, IPV6, DOMAIN, URL, HASH)
RULES: Final = {kind: f"ungrounded_{kind}" for kind in KINDS}

Ioc = tuple[str, str]  # (kind, canonical value)

_DEFANG: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[\s{0,2}\.\s{0,2}\]|\(\s{0,2}\.\s{0,2}\)|\{\s{0,2}\.\s{0,2}\}"), "."),
    (re.compile(r"\[dot\]|\(dot\)|\{dot\}"), "."),
    (re.compile(r"\bhxxp"), "http"),
    (re.compile(r"\bfxp://"), "ftp://"),
)

_IPV4_RE: Final = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d)")
_IPV6_RE: Final = re.compile(r"(?<![\w:.])([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?![\w:]|\.\d)")
_HASH_RE: Final = re.compile(r"(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])")
_URL_RE: Final = re.compile(r"(?<!\w)((?:https?|ftp)://[^\s\"'<>\\`]{1,2048})")
_URL_TRAILING: Final = ".,;:!?)]}'\""
# Unicode letters are allowed in labels, so an internationalized or lookalike domain is still
# an indicator. A label never starts or ends with "-" or "_".
_LABEL: Final = r"[^\W_](?:[\w-]{0,61}[^\W_])?"
_DOMAIN_RE: Final = re.compile(
    r"(?<![\w.-])((?:" + _LABEL + r"\.){1,16}([^\W\d_]{2,24}))(?![\w-]|\.[^\W_])"
)
FILE_EXTENSIONS: Final = frozenset(
    {
        "asp", "aspx", "bat", "bin", "cfg", "cmd", "conf", "csv", "dat", "dll", "doc", "docx",
        "exe", "htm", "html", "ini", "jar", "js", "json", "jsp", "lnk", "log", "msi", "php", "ps1",
        "psm1", "scr", "sys", "tmp", "txt", "vbs", "xls", "xlsx", "xml", "yaml", "yml",
    }
)  # fmt: skip


def normalize(text: str) -> str:
    """The text both sides are compared in: sanitizer-normalized, case-folded, refanged."""
    folded = normalize_text(text).casefold()
    for pattern, replacement in _DEFANG:
        folded = pattern.sub(replacement, folded)
    return folded


def _ipv4(raw: str) -> str | None:
    octets = raw.split(".")
    if any(int(octet) > 255 for octet in octets):
        return None
    return ".".join(str(int(octet)) for octet in octets)


def _ipv6(raw: str) -> str | None:
    if not raw.strip(":"):  # "::" alone is the unspecified address, not an indicator
        return None
    try:
        return IPv6Address(raw).compressed
    except ValueError:
        return None


def extract(text: str) -> set[Ioc]:
    """The indicators in ``text`` (already normalized), as canonical (kind, value) pairs."""
    found: set[Ioc] = set()
    for match in _IPV4_RE.finditer(text):
        value = _ipv4(match.group(1))
        if value is not None:
            found.add((IPV4, value))
    for match in _IPV6_RE.finditer(text):
        value = _ipv6(match.group(1))
        if value is not None:
            found.add((IPV6, value))
    for match in _HASH_RE.finditer(text):
        found.add((HASH, match.group(1)))
    for match in _URL_RE.finditer(text):
        url = match.group(1).rstrip(_URL_TRAILING)
        if "://" in url and not url.endswith("://"):
            found.add((URL, url))
    for match in _DOMAIN_RE.finditer(text):
        if match.group(2) not in FILE_EXTENSIONS:
            found.add((DOMAIN, match.group(1)))
    return found


def _alert_texts(alert: Alert) -> Iterable[str]:
    for name in Alert.model_fields:
        value = getattr(alert, name)
        if isinstance(value, str):
            yield value
        elif isinstance(value, IPv4Address | IPv6Address):
            yield str(value)


def grounded_set(alert: Alert) -> set[Ioc]:
    """Every indicator the alert contains, plus the parent domains of its domains."""
    found: set[Ioc] = set()
    for text in _alert_texts(alert):
        found |= extract(normalize(text))
    for kind, value in list(found):
        if kind == DOMAIN:
            labels = value.split(".")
            for start in range(1, len(labels) - 1):
                found.add((DOMAIN, ".".join(labels[start:])))
    return found


def ungrounded(output_texts: Iterable[str], alert: Alert) -> set[Ioc]:
    """The indicators in ``output_texts`` that the alert does not contain."""
    claimed: set[Ioc] = set()
    for text in output_texts:
        claimed |= extract(normalize(text))
    return claimed - grounded_set(alert)


def check(ctx: Context) -> list[str]:
    missing = ungrounded(ctx.view.strings, ctx.alert)
    return [RULES[kind] for kind in KINDS if any(k == kind for k, _ in missing)]
