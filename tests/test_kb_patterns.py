"""Batch aggregation (D41): spraying, brute force and the explicit "undetermined" outcome."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ai_security_assistant.kb import load_kb
from ai_security_assistant.kb.patterns import batch_patterns
from ai_security_assistant.models import Alert

START = datetime(2026, 8, 10, 9, 0, 0, tzinfo=UTC)


def failed(
    user: str | None,
    ip: str | None = "192.0.2.66",
    offset: float = 0,
    event_id: str | None = "4625",
) -> Alert:
    return Alert(
        source="wazuh",
        timestamp=START + timedelta(seconds=offset),
        id=f"a-{user}-{offset}",
        rule_id="60122",
        severity_raw="5",
        event_id=event_id,
        target_user=user,
        src_ip_raw=ip,
    )


def group(users: int, attempts: int, ip: str = "192.0.2.66") -> list[Alert]:
    return [
        failed(f"user{u}", ip, offset=u * 10 + a) for u in range(users) for a in range(attempts)
    ]


def pattern_of(alerts: list[Alert]) -> dict[int, str]:
    return {index: fact.pattern for index, fact in batch_patterns(alerts).items()}


# ------------------------------------------------------------------ thresholds at each boundary


@pytest.mark.parametrize(
    ("users", "attempts", "expected"),
    [
        (4, 1, "password_spraying"),  # the boundary: 4 users
        (4, 2, "password_spraying"),  # the boundary: 2 attempts each
        (10, 1, "password_spraying"),
        (3, 1, "undetermined"),  # one user short
        (3, 2, "undetermined"),
        (4, 3, "undetermined"),  # one attempt too many for spraying
        (5, 4, "undetermined"),  # the owner's example
        (2, 10, "undetermined"),  # the owner's example
        (1, 5, "brute_force"),  # the boundary: 5 attempts
        (1, 20, "brute_force"),
        (1, 4, "undetermined"),  # one attempt short
        (1, 1, "undetermined"),
        (2, 5, "undetermined"),  # not one user, not enough users
    ],
)
def test_thresholds_at_each_boundary(users: int, attempts: int, expected: str) -> None:
    alerts = group(users, attempts)
    result = pattern_of(alerts)
    assert set(result) == set(range(len(alerts)))
    assert set(result.values()) == {expected}


def test_a_mixed_group_with_one_busy_user_is_not_spraying() -> None:
    alerts = [failed(f"u{i}", offset=i) for i in range(4)] + [
        failed("u0", offset=9),
        failed("u0", offset=10),
    ]
    assert set(pattern_of(alerts).values()) == {"undetermined"}  # A = 3


def test_the_techniques_and_counts_come_from_the_table_and_the_group() -> None:
    spraying = batch_patterns(group(5, 2))[0]
    assert spraying.technique == "T1110.003"
    assert (spraying.distinct_users, spraying.max_attempts_per_user, spraying.attempts) == (
        5,
        2,
        10,
    )
    assert spraying.window_seconds == load_kb().patterns.window_seconds
    assert spraying.meaning == load_kb().patterns.password_spraying.meaning
    brute = batch_patterns(group(1, 7))[0]
    assert (brute.technique, brute.pattern) == ("T1110.001", "brute_force")
    assert (brute.distinct_users, brute.max_attempts_per_user, brute.attempts) == (1, 7, 7)
    unknown = batch_patterns(group(2, 10))[0]
    assert unknown.technique is None
    assert unknown.meaning == load_kb().patterns.undetermined.meaning


def test_a_pattern_fact_holds_no_user_name() -> None:
    fact = batch_patterns(group(4, 1))[0]
    assert "user0" not in repr(fact) and "user0" not in str(fact.to_dict())


# ------------------------------------------------------------------ groups split by address


def test_groups_are_split_by_source_address() -> None:
    # Four users but spread over two addresses: each address sees two users only.
    alerts = [
        failed("a", "192.0.2.1"),
        failed("b", "192.0.2.1"),
        failed("c", "192.0.2.2"),
        failed("d", "192.0.2.2"),
    ]
    assert set(pattern_of(alerts).values()) == {"undetermined"}
    # The same four users from one address are spraying.
    alerts = [failed(u, "192.0.2.1") for u in "abcd"]
    assert set(pattern_of(alerts).values()) == {"password_spraying"}


def test_each_address_gets_its_own_pattern() -> None:
    alerts = group(4, 1, "192.0.2.1") + group(1, 5, "192.0.2.2")
    result = pattern_of(alerts)
    assert {result[i] for i in range(4)} == {"password_spraying"}
    assert {result[i] for i in range(4, 9)} == {"brute_force"}


def test_distributed_spraying_across_many_addresses_is_a_known_blind_spot() -> None:
    """One user per address, one attempt each: nothing is flagged. Documented in T14."""
    alerts = [failed(f"user{i}", f"192.0.2.{i + 1}") for i in range(8)]
    assert set(pattern_of(alerts).values()) == {"undetermined"}


def test_ipv6_addresses_group_like_any_other() -> None:
    alerts = [failed(u, "2001:db8::1") for u in "abcd"]
    assert set(pattern_of(alerts).values()) == {"password_spraying"}


# ------------------------------------------------------------------ groups split by window


def test_a_group_is_anchored_at_its_first_event_and_the_window_is_inclusive() -> None:
    window = load_kb().patterns.window_seconds
    inside = [
        failed(u, offset=i * (window / 3)) for i, u in enumerate("abcd")
    ]  # last at exactly +window
    assert inside[-1].timestamp - inside[0].timestamp == timedelta(seconds=window)
    assert set(pattern_of(inside).values()) == {"password_spraying"}


def test_an_event_just_past_the_window_opens_a_new_group() -> None:
    window = load_kb().patterns.window_seconds
    alerts = [failed(u, offset=i) for i, u in enumerate("abc")] + [failed("d", offset=window + 1)]
    result = batch_patterns(alerts)
    assert {result[i].pattern for i in range(3)} == {"undetermined"}  # 3 users: one short
    assert result[3].pattern == "undetermined"
    assert result[3].distinct_users == 1
    assert result[0].distinct_users == 3


def test_low_and_slow_spraying_slower_than_the_window_is_a_known_blind_spot() -> None:
    window = load_kb().patterns.window_seconds
    alerts = [failed(u, offset=i * (window + 60)) for i, u in enumerate("abcdef")]
    assert set(pattern_of(alerts).values()) == {"undetermined"}


def test_a_later_window_can_be_a_pattern_of_its_own() -> None:
    window = load_kb().patterns.window_seconds
    late = window * 3
    alerts = [failed("x", offset=0)] + [failed(u, offset=late + i) for i, u in enumerate("abcd")]
    result = batch_patterns(alerts)
    assert result[0].pattern == "undetermined"
    assert {result[i].pattern for i in range(1, 5)} == {"password_spraying"}


def test_events_out_of_input_order_are_grouped_by_time() -> None:
    alerts = [
        failed("d", offset=30),
        failed("a", offset=0),
        failed("c", offset=20),
        failed("b", offset=10),
    ]
    assert set(pattern_of(alerts).values()) == {"password_spraying"}


# ------------------------------------------------------------------ who counts


def test_other_events_and_alerts_without_a_key_are_not_part_of_a_group() -> None:
    alerts = [
        failed("a"),
        failed("b", event_id="4624"),  # a success is not a failed logon
        failed("c", event_id=None),
        failed("d", event_id="04625"),  # not a canonical key
        failed("e", ip=None),  # no source address
        failed("f", ip="not-an-ip"),
        failed(None),  # no user name
    ]
    assert set(batch_patterns(alerts)) == {0}
    assert batch_patterns(alerts)[0].attempts == 1


@pytest.mark.parametrize("name", ["", " ", "-", " - "])
def test_a_missing_user_name_is_not_counted(name: str) -> None:
    alerts = [failed(u) for u in "abc"] + [failed(name)]
    assert set(batch_patterns(alerts)) == {0, 1, 2}


def test_user_names_are_compared_trimmed_and_case_folded() -> None:
    alerts = [
        failed("Admin"),
        failed("admin "),
        failed(" ADMIN", offset=3),
        failed("admin", offset=4),
        failed("Admin", offset=5),
    ]
    fact = batch_patterns(alerts)[0]
    assert (fact.pattern, fact.distinct_users, fact.attempts) == ("brute_force", 1, 5)


def test_loopback_values_are_kept_but_never_make_a_pattern_without_real_counts() -> None:
    assert set(pattern_of([failed("a", "127.0.0.1"), failed("b", "127.0.0.1")]).values()) == {
        "undetermined"
    }
    assert set(pattern_of([failed("a", "::1")]).values()) == {"undetermined"}
    # With real counts the address is treated like any other.
    assert set(pattern_of(group(4, 1, "127.0.0.1")).values()) == {"password_spraying"}


def test_an_empty_batch_has_no_patterns() -> None:
    assert batch_patterns([]) == {}


# ------------------------------------------------------------------ the whole batch


def test_the_pattern_is_computed_over_the_whole_batch_not_per_alert() -> None:
    """One alert alone is not a pattern; the same alert inside its batch is part of one."""
    alerts = group(4, 1)
    alone = batch_patterns(alerts[:1])
    together = batch_patterns(alerts)
    assert alone[0].pattern == "undetermined"
    assert together[0].pattern == "password_spraying"
    assert together[0] == together[3]  # every member of the group carries the same fact
