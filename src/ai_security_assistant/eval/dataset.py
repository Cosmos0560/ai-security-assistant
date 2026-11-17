"""The eval dataset (D21, D24, D34): 120 synthetic alerts with labels, in the package data.

Each line of ``data/eval/alerts.jsonl`` is one JSON object with exactly these keys:

* ``sample_id``     ``s001`` ... unique;
* ``label``         ``benign`` or ``injection``;
* ``category``      one of the eight D21 categories for an injection, else null;
* ``attack_goal``   one of the six goals for an injection (D23 plus ``summary_manipulation``,
                    D34), else null;
* ``goal_target``   what the goal needs to be checked: the forced severity for
                    ``forced_severity``, the marker phrase for ``summary_manipulation``, else null;
* ``hard_negative`` true for a benign alert written to look suspicious, else false;
* ``split``         ``dev`` or ``heldout`` (D24);
* ``format``        the source format of ``record``: ``wazuh``, ``mini-siem`` or
                    ``soc-log-analyzer``;
* ``record``        ONE source-native record. A soc-log-analyzer alert is wrapped into a
                    ``stored_alerts`` document before parsing, the way the tool writes it.

Every record goes through the real ingest adapter, so the eval sees exactly what ``aisa triage``
would. Any deviation is a ``DatasetError``; there is no partial dataset.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final

from ai_security_assistant.ingest import ADAPTERS, IngestError
from ai_security_assistant.models import Alert
from ai_security_assistant.schema import Severity

LABELS: Final = ("benign", "injection")
CATEGORIES: Final = (
    "direct_override",
    "role_play",
    "delimiter_escape",
    "encoded_payload",
    "output_format_hijack",
    "ioc_bait",
    "prompt_exfiltration",
    "non_english",
)
ATTACK_GOALS: Final = (
    "forced_severity",
    "off_allowlist_action",
    "canary_leak",
    "ungrounded_ioc",
    "non_json",
    "summary_manipulation",
)
GOALS_WITH_TARGET: Final = frozenset({"forced_severity", "summary_manipulation"})
SPLITS: Final = ("dev", "heldout")
FORMATS: Final = ("wazuh", "mini-siem", "soc-log-analyzer")
KEYS: Final = frozenset(
    {
        "sample_id",
        "label",
        "category",
        "attack_goal",
        "goal_target",
        "hard_negative",
        "split",
        "format",
        "record",
    }
)
DATA_PACKAGE: Final = "ai_security_assistant"
DATA_PATH: Final = ("data", "eval", "alerts.jsonl")


class DatasetError(ValueError):
    """The dataset file does not have the documented shape."""


@dataclass(frozen=True)
class Sample:
    sample_id: str
    label: str
    category: str | None
    attack_goal: str | None
    goal_target: str | None
    hard_negative: bool
    split: str
    format: str
    alert: Alert

    @property
    def is_injection(self) -> bool:
        return self.label == "injection"


def dataset_text() -> str:
    """The packaged dataset, CRLF normalized to LF (D29)."""
    resource = resources.files(DATA_PACKAGE).joinpath(*DATA_PATH)
    return resource.read_text(encoding="utf-8").replace("\r\n", "\n")


def dataset_sha256(text: str | None = None) -> str:
    data = dataset_text() if text is None else text.replace("\r\n", "\n")
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _alert(fmt: str, record: object, label: str) -> Alert:
    adapter = next(a for a in ADAPTERS if a.name == fmt)
    document: object = record
    if fmt == "soc-log-analyzer":
        document = {"schema_version": "1.0", "kind": "stored_alerts", "alerts": [record]}
    try:
        (alert,) = adapter.parse([document])
    except IngestError as exc:
        raise DatasetError(f"{label}: record does not ingest: {exc}") from None
    return alert


def _optional_str(row: dict[str, Any], key: str, label: str) -> str | None:
    value = row[key]
    if value is not None and not (isinstance(value, str) and value):
        raise DatasetError(f"{label}: {key} must be a non-empty string or null")
    return value


def parse_row(row: object, number: int) -> Sample:
    label = f"dataset line {number}"
    if not isinstance(row, dict) or set(row) != KEYS:
        raise DatasetError(f"{label}: expected an object with exactly the documented keys")
    sample_id = row["sample_id"]
    if not isinstance(sample_id, str) or not sample_id:
        raise DatasetError(f"{label}: sample_id must be a non-empty string")
    if row["label"] not in LABELS:
        raise DatasetError(f"{label}: unknown label")
    if row["split"] not in SPLITS:
        raise DatasetError(f"{label}: unknown split")
    if row["format"] not in FORMATS:
        raise DatasetError(f"{label}: unknown format")
    if not isinstance(row["hard_negative"], bool):
        raise DatasetError(f"{label}: hard_negative must be a boolean")
    category = _optional_str(row, "category", label)
    goal = _optional_str(row, "attack_goal", label)
    target = _optional_str(row, "goal_target", label)
    if row["label"] == "benign":
        if category is not None or goal is not None or target is not None:
            raise DatasetError(f"{label}: a benign sample has no category, goal or target")
    else:
        if category not in CATEGORIES or goal not in ATTACK_GOALS:
            raise DatasetError(f"{label}: an injection needs a known category and attack_goal")
        if row["hard_negative"]:
            raise DatasetError(f"{label}: only a benign sample can be a hard negative")
        if (target is not None) is not (goal in GOALS_WITH_TARGET):
            raise DatasetError(f"{label}: goal_target is set exactly for goals that need one")
        if goal == "forced_severity" and target not in {s.value for s in Severity}:
            raise DatasetError(f"{label}: a forced_severity target must be a severity")
    return Sample(
        sample_id=sample_id,
        label=row["label"],
        category=category,
        attack_goal=goal,
        goal_target=target,
        hard_negative=row["hard_negative"],
        split=row["split"],
        format=row["format"],
        alert=_alert(row["format"], row["record"], label),
    )


def parse_dataset(text: str) -> list[Sample]:
    """Every sample in ``text`` (JSONL). Raises ``DatasetError`` on the first problem."""
    samples: list[Sample] = []
    for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            raise DatasetError(f"dataset line {number}: not valid JSON") from None
        samples.append(parse_row(row, number))
    ids = [sample.sample_id for sample in samples]
    if len(set(ids)) != len(ids):
        raise DatasetError("sample_id values are not unique")
    if not samples:
        raise DatasetError("the dataset is empty")
    return samples


def load_dataset() -> list[Sample]:
    """The packaged dataset, parsed and checked."""
    return parse_dataset(dataset_text())
