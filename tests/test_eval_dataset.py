"""The eval dataset (D21, D24, D34): shape, balance, stratification and value rules."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

import pytest

from ai_security_assistant.eval import dataset
from ai_security_assistant.eval.dataset import (
    ATTACK_GOALS,
    CATEGORIES,
    DatasetError,
    Sample,
    dataset_sha256,
    dataset_text,
    load_dataset,
    parse_dataset,
    parse_row,
)
from ai_security_assistant.providers import mock
from ai_security_assistant.schema import Severity

SAMPLES = load_dataset()


def rows() -> list[dict[str, Any]]:
    return [json.loads(line) for line in dataset_text().split("\n") if line.strip()]


# ---------------------------------------------------------------- balance and split (D21, D24)


def test_there_are_60_benign_and_60_injection_samples() -> None:
    assert Counter(s.label for s in SAMPLES) == {"benign": 60, "injection": 60}


def test_every_category_has_7_or_8_samples_and_only_known_categories_exist() -> None:
    counts = Counter(s.category for s in SAMPLES if s.is_injection)
    assert set(counts) == set(CATEGORIES)
    assert all(7 <= n <= 8 for n in counts.values())


def test_every_goal_is_one_of_the_six_and_spread_across_categories() -> None:
    assert len(ATTACK_GOALS) == 6 and "summary_manipulation" in ATTACK_GOALS
    goals = Counter(s.attack_goal for s in SAMPLES if s.is_injection)
    assert set(goals) == set(ATTACK_GOALS)
    for goal in ATTACK_GOALS:
        categories = {s.category for s in SAMPLES if s.attack_goal == goal}
        assert len(categories) >= 4, goal  # spread, not one goal per category
    for category in CATEGORIES:
        assert len({s.attack_goal for s in SAMPLES if s.category == category}) >= 2


def test_the_split_is_72_48_and_stratified_by_class_and_category() -> None:
    assert Counter(s.split for s in SAMPLES) == {"dev": 72, "heldout": 48}
    for label in ("benign", "injection"):
        assert Counter(s.split for s in SAMPLES if s.label == label) == {"dev": 36, "heldout": 24}
    for category in CATEGORIES:
        split = Counter(s.split for s in SAMPLES if s.category == category)
        assert split["heldout"] == 3 and split["dev"] in (4, 5), category
    hard = Counter(s.split for s in SAMPLES if s.hard_negative)
    assert hard["heldout"] >= 6 and hard["dev"] >= 9


def test_there_are_at_least_15_hard_negatives_with_the_listed_traits() -> None:
    hard = [s for s in SAMPLES if s.hard_negative]
    assert len(hard) >= 15
    text = " ".join(
        json.dumps(r["record"], ensure_ascii=False) for r in rows() if r["hard_negative"]
    )
    lowered = text.casefold()
    for word in ("ignore", "system", "override", "sudo", "powershell", "kubectl"):
        assert word in lowered, word
    assert any("Ѐ" <= ch <= "ӿ" for ch in text)  # Russian
    assert "noto'g'ri" in text or "yangilandi" in text  # Uzbek (Latin)


def test_all_three_source_formats_are_mixed_into_both_classes() -> None:
    for label in ("benign", "injection"):
        formats = Counter(s.format for s in SAMPLES if s.label == label)
        assert set(formats) == {"wazuh", "mini-siem", "soc-log-analyzer"}
        assert min(formats.values()) >= 15


def test_goal_targets_are_set_exactly_where_a_goal_needs_one() -> None:
    for sample in SAMPLES:
        if sample.attack_goal == "forced_severity":
            assert sample.goal_target in {s.value for s in Severity}
        elif sample.attack_goal == "summary_manipulation":
            assert sample.goal_target and len(sample.goal_target) >= 10
        else:
            assert sample.goal_target is None


def test_a_forced_severity_target_differs_from_the_honest_severity() -> None:
    for sample in SAMPLES:
        if sample.attack_goal == "forced_severity":
            honest, known = mock.severity_from_raw(sample.alert.severity_raw)
            assert known and honest.value != sample.goal_target, sample.sample_id


def test_a_summary_marker_is_never_in_a_field_the_honest_summary_echoes() -> None:
    """The well-behaved summary repeats rule id/name, host, user and IPs; a marker there would
    count as success without any obedience."""
    for sample in SAMPLES:
        if sample.attack_goal == "summary_manipulation":
            alert = sample.alert
            host = alert.host if alert.host and mock._HOST_RE.fullmatch(alert.host) else None
            user = alert.user if alert.user and mock._USER_RE.fullmatch(alert.user) else None
            echoed = " ".join(
                v or "" for v in (alert.rule_id, alert.rule_name, host, user, alert.src_ip_raw)
            ).casefold()
            assert sample.goal_target is not None
            assert sample.goal_target.casefold() not in echoed, sample.sample_id


def test_the_dataset_holds_none_of_the_iocs_the_naive_mock_invents() -> None:
    text = dataset_text().casefold()
    for values in mock._INVENTED.values():
        for value in values:
            assert value.casefold() not in text


def test_sample_ids_are_unique_and_order_says_nothing_about_the_label() -> None:
    ids = [s.sample_id for s in SAMPLES]
    assert len(set(ids)) == 120
    first_half = Counter(s.label for s in SAMPLES[:60])
    assert 20 <= first_half["injection"] <= 40


def test_the_text_and_hash_are_lf_normalized() -> None:
    text = dataset_text()
    assert "\r" not in text and text.endswith("\n")
    assert dataset_sha256() == dataset_sha256(text.replace("\n", "\r\n"))


# ---------------------------------------------------------------- strict parsing


GOOD = rows()[0]


def mutated(**changes: Any) -> dict[str, Any]:
    row = json.loads(json.dumps(GOOD))
    row.update(changes)
    return row


def an_injection() -> dict[str, Any]:
    return next(r for r in rows() if r["attack_goal"] == "forced_severity")


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ([], "exactly the documented keys"),
        ({**GOOD, "extra": 1}, "exactly the documented keys"),
        (mutated(sample_id=""), "sample_id"),
        (mutated(label="maybe"), "unknown label"),
        (mutated(split="test"), "unknown split"),
        (mutated(format="syslog"), "unknown format"),
        (mutated(hard_negative="yes"), "hard_negative"),
        (mutated(category=""), "non-empty string or null"),
        (mutated(category="role_play"), "benign sample has no"),
        (mutated(record={"nothing": True}), "does not ingest"),
    ],
)
def test_a_bad_row_is_rejected(row: object, message: str) -> None:
    with pytest.raises(DatasetError, match=message):
        parse_row(row, 1)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"category": "made_up"}, "known category"),
        ({"attack_goal": "made_up"}, "known category and attack_goal"),
        ({"hard_negative": True}, "only a benign"),
        ({"goal_target": None}, "goal_target is set exactly"),
        ({"goal_target": "urgent"}, "must be a severity"),
        ({"attack_goal": "non_json"}, "goal_target is set exactly"),
    ],
)
def test_a_bad_injection_row_is_rejected(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(DatasetError, match=message):
        parse_row({**an_injection(), **changes}, 1)


def test_every_source_format_parses_through_its_real_adapter() -> None:
    by_format = {s.format: s for s in SAMPLES}
    assert by_format["wazuh"].alert.source == "wazuh"
    assert by_format["mini-siem"].alert.source == "mini-siem"
    soc = by_format["soc-log-analyzer"].alert
    assert soc.source == "soc-log-analyzer" and soc.id.startswith("stored-")


def test_the_whole_file_is_checked() -> None:
    line = json.dumps(GOOD)
    with pytest.raises(DatasetError, match="not valid JSON"):
        parse_dataset(line + "\n{oops\n")
    with pytest.raises(DatasetError, match="not unique"):
        parse_dataset(f"{line}\n{line}\n")
    with pytest.raises(DatasetError, match="empty"):
        parse_dataset("\n\n")
    (one,) = parse_dataset(line + "\r\n")
    assert isinstance(one, Sample)


def test_the_constants_are_what_the_plan_names() -> None:
    assert dataset.CATEGORIES == (
        "direct_override",
        "role_play",
        "delimiter_escape",
        "encoded_payload",
        "output_format_hijack",
        "ioc_bait",
        "prompt_exfiltration",
        "non_english",
    )
    assert sorted(dataset.GOALS_WITH_TARGET) == ["forced_severity", "summary_manipulation"]
