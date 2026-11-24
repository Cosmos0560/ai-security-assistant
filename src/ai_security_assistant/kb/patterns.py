"""Batch aggregation of failed logons: password spraying vs brute force (D41).

Before the per-alert loop, the WHOLE input batch is scanned for failed logons (the event ID in the
table's ``patterns.event_id``, 4625) with a parsed source address and a user name. One source
address is one group, and a group is closed by a time window that is anchored at its first
event (so a burst is not split by a clock boundary): an event joins the open group when it is at
most ``window_seconds`` after the group's FIRST event, otherwise it opens the next group. Within
a group, U is the number of distinct user names and A the highest attempt count of one user:

* U at least ``min_distinct_users`` and A at most ``max_attempts_per_user``: ``password_spraying``;
* U equal to ``distinct_users`` and A at least ``min_attempts``: ``brute_force``;
* anything else: ``undetermined``. A group is never forced into one of the two techniques.

The thresholds are data (``windows_kb.json``). The pattern is evidence, not a verdict.

What it cannot see (documented blind spots, T14):

* distributed spraying: the same few passwords from MANY source addresses give one small group
  per address, and each is ``undetermined``;
* low-and-slow spraying slower than the window: each window holds too few events;
* user names are attacker-controlled text, so whoever writes the log can make a group look like
  either pattern.

Only the counts leave this module as facts. A user name is compared (trimmed, case-folded) and
discarded; it is never stored in a ``PatternFact``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from ai_security_assistant.kb import (
    KnowledgeBase,
    PatternFact,
    PatternName,
    canonical_event_id,
    load_kb,
)
from ai_security_assistant.models import Alert

MISSING_USER = "-"  # what Windows writes when there is no user name


def _user_key(raw: str | None) -> str | None:
    """The comparison key of a user name, or ``None`` when there is no usable name."""
    if raw is None:
        return None
    key = raw.strip().casefold()
    return None if key in {"", MISSING_USER} else key


def _classify(users: Counter[str], kb: KnowledgeBase) -> PatternFact:
    rules = kb.patterns
    distinct = len(users)
    most = max(users.values())
    attempts = sum(users.values())
    spraying, brute = rules.password_spraying, rules.brute_force
    name: PatternName
    technique: str | None
    if distinct >= spraying.min_distinct_users and most <= spraying.max_attempts_per_user:
        name, technique, meaning = "password_spraying", spraying.technique, spraying.meaning
    elif distinct == brute.distinct_users and most >= brute.min_attempts:
        name, technique, meaning = "brute_force", brute.technique, brute.meaning
    else:
        name, technique, meaning = "undetermined", None, rules.undetermined.meaning
    return PatternFact(
        pattern=name,
        technique=technique,
        meaning=meaning,
        window_seconds=rules.window_seconds,
        distinct_users=distinct,
        max_attempts_per_user=most,
        attempts=attempts,
    )


def batch_patterns(
    alerts: Sequence[Alert], kb: KnowledgeBase | None = None
) -> dict[int, PatternFact]:
    """The pattern fact of every failed-logon alert that has a group, keyed by its list index.

    An alert without a parsed source address, or without a usable user name, belongs to no group
    and gets no fact. Loopback and other addresses are treated like any other: a pattern needs
    real user and attempt counts, never the address alone.
    """
    table = load_kb() if kb is None else kb
    window = table.patterns.window_seconds
    by_source: dict[IPv4Address | IPv6Address, list[tuple[datetime, int, str]]] = {}
    for index, alert in enumerate(alerts):
        if canonical_event_id(alert.event_id) != table.patterns.event_id or alert.src_ip is None:
            continue
        user = _user_key(alert.target_user)
        if user is not None:
            by_source.setdefault(alert.src_ip, []).append((alert.timestamp, index, user))
    result: dict[int, PatternFact] = {}
    for events in by_source.values():
        events.sort()
        group: list[tuple[datetime, int, str]] = []
        for event in [*events, None]:
            if event is not None and (
                not group or (event[0] - group[0][0]).total_seconds() <= window
            ):
                group.append(event)
                continue
            fact = _classify(Counter(user for _ts, _index, user in group), table)
            for _ts, index, _user in group:
                result[index] = fact
            group = [] if event is None else [event]
    return result
