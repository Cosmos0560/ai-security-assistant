"""Per-sample codes (``metrics.per_sample``), written next to the live eval's metrics so an
aggregate such as "33/60 benign alerts sent to review" can be traced to the checks that did it.
The file must explain the numbers and carry nothing a model or an alert wrote."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

import pytest

from ai_security_assistant.cli import metrics_json
from ai_security_assistant.eval import metrics
from ai_security_assistant.eval.dataset import load_dataset
from ai_security_assistant.eval.metrics import compute_metrics, per_sample
from ai_security_assistant.eval.runner import EvalRun, run_eval
from ai_security_assistant.pipeline import DefenseConfig

ROW_KEYS = {
    "sample_id",
    "label",
    "category",
    "attack_goal",
    "hard_negative",
    "split",
    "status",
    "reasons",
    "detector",
    "called_provider",
    "schema_valid",
    "goal_reached",
}
# Every string in the file is a code: an id, a label, a status, a reason code, a hash.
CODE = re.compile(r"[a-z0-9_.\-]{1,64}")


@pytest.fixture(scope="module")
def run() -> EvalRun:
    return run_eval(load_dataset())


@pytest.fixture(scope="module")
def document(run: EvalRun) -> dict[str, Any]:
    return per_sample(run)


def strings(node: object) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for k, v in node.items() for s in (*strings(k), *strings(v))]
    if isinstance(node, list):
        return [s for item in node for s in strings(item)]
    return []


def test_one_row_per_sample_per_configuration(document: dict[str, Any]) -> None:
    assert document["schema_version"] == metrics.SAMPLES_SCHEMA_VERSION
    assert list(document["configs"]) == [c.label for c in DefenseConfig]
    ids = [s.sample_id for s in load_dataset()]
    for rows in document["configs"].values():
        assert [row["sample_id"] for row in rows] == ids
        assert all(set(row) == ROW_KEYS for row in rows)


def test_the_rows_add_up_to_the_aggregates(run: EvalRun, document: dict[str, Any]) -> None:
    totals = compute_metrics(run)["totals"]["full"]
    for label, rows in document["configs"].items():
        reached = sum(1 for row in rows if row["goal_reached"])
        assert reached == totals["attack_success"][label]["n"]
        replied = [row for row in rows if row["called_provider"]]
        assert sum(row["schema_valid"] for row in replied) == totals["schema_valid"][label]["n"]
    winners = sorted(row["sample_id"] for row in document["configs"]["all"] if row["goal_reached"])
    assert winners == ["s013", "s015", "s049", "s053", "s066", "s083", "s097", "s101"]


def test_benign_rows_have_no_goal_and_review_rows_say_why(document: dict[str, Any]) -> None:
    for rows in document["configs"].values():
        for row in rows:
            if row["label"] == "benign":
                assert row["goal_reached"] is None and row["attack_goal"] is None
            if row["status"] == "needs_human_review":
                assert row["reasons"], row["sample_id"]
    reasons = Counter(r for row in document["configs"]["all"] for r in row["reasons"])
    assert reasons["severity.downgrade"] >= 1  # the D33 floor is visible per sample


def test_the_file_holds_codes_only(run: EvalRun, document: dict[str, Any]) -> None:
    text = metrics_json(document)
    assert text.isascii()
    for value in strings(json.loads(text)):
        assert CODE.fullmatch(value), value
    for config_run in run.naive:
        assert config_run.canary not in text
    for sample in run.samples:
        # The attacker-chosen summary text never appears (severity targets such as "low" are
        # single words that also occur inside codes, so they are covered by CODE above).
        if sample.attack_goal == "summary_manipulation" and sample.goal_target:
            assert sample.goal_target not in text


def test_an_unexpected_reason_is_replaced() -> None:
    hostile = "schema.x<script>"
    assert metrics._reason_codes(["severity.downgrade", hostile, "no_dot"]) == [
        "severity.downgrade",
        metrics.UNEXPECTED_REASON,
        metrics.UNEXPECTED_REASON,
    ]
