"""The eval datasets, in the package data: the main set (D21, D24, D34; 120 synthetic alerts) and
the Windows-auth set (D43).

Each line of the main set, ``data/eval/alerts.jsonl``, is one JSON object with exactly these keys:

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

The Windows-auth set, ``data/eval/windows_auth.jsonl``, holds Wazuh records only (``w001`` ...)
and has no split and no hard negatives. Its rows share ``sample_id``, ``label``, ``category``,
``attack_goal``, ``goal_target`` and ``record``, and add:

* ``group``                 which case the alert belongs to (``WINDOWS_GROUPS``);
* ``expected_technique``    the ground-truth technique, or null for ordinary activity that is no
                            attack: its technique is not scored (the schema still makes the model
                            name one);
* ``expected_min_severity`` the lowest severity a correct triage may give;
* ``truth_pattern``         what the failed logons REALLY are, or null when not assessed;
* ``known_miss``            the documented D41 blind spot the alert sits in, or null.

There ``label`` keeps the main set's meaning: ``benign`` is "no injected instructions", so the
alerts of a real spraying or brute-force group are ``benign`` too. ``attack_goal`` may also be
``fact_misstatement``, which only this set uses.

Two known limits of the set, both kept on purpose: one injection sits in ``workstationName``, which
the Wazuh adapter drops, so the model never sees that payload (it still counts as an injection and
costs a call); and one Russian-locale 4625 is too long for the Ollama context budget once its
Cyrillic is escaped, so the local model is asked about it only under ``none``.

Every record goes through the real ingest adapter, so the eval sees exactly what ``aisa triage``
would. Any deviation is a ``DatasetError``; there is no partial dataset.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final, TypeVar

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
FACT_MISSTATEMENT: Final = "fact_misstatement"  # D43: the Windows set only
WINDOWS_GOALS: Final = (*ATTACK_GOALS, FACT_MISSTATEMENT)
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
DATASET_NAMES: Final = ("main", "windows")
NO_SPLIT: Final = "unsplit"  # the split of every Windows sample
WINDOWS_GROUPS: Final = (
    "single",
    "lockout",
    "spraying",
    "brute_force",
    "undetermined_2_users",
    "undetermined_5_users",
    "distributed_spraying",
    "low_and_slow_spraying",
    "locale_ru",
    "injection",
)
TRUTH_PATTERNS: Final = ("password_spraying", "brute_force", "undetermined")
KNOWN_MISSES: Final = ("distributed_spraying", "low_and_slow_spraying")
WINDOWS_KEYS: Final = frozenset(
    {
        "sample_id",
        "label",
        "category",
        "attack_goal",
        "goal_target",
        "group",
        "expected_technique",
        "expected_min_severity",
        "truth_pattern",
        "known_miss",
        "record",
    }
)
DATA_PACKAGE: Final = "ai_security_assistant"
DATA_PATH: Final = ("data", "eval", "alerts.jsonl")
WINDOWS_PATH: Final = ("data", "eval", "windows_auth.jsonl")


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


@dataclass(frozen=True)
class WindowsSample(Sample):
    """A sample of the Windows-auth set, with its ground truth (D43)."""

    group: str
    expected_technique: str | None
    expected_min_severity: Severity
    truth_pattern: str | None
    known_miss: str | None


def _packaged(path: tuple[str, ...]) -> str:
    resource = resources.files(DATA_PACKAGE).joinpath(*path)
    return resource.read_text(encoding="utf-8").replace("\r\n", "\n")


def dataset_text() -> str:
    """The packaged main dataset, CRLF normalized to LF (D29)."""
    return _packaged(DATA_PATH)


def windows_dataset_text() -> str:
    """The packaged Windows-auth dataset, CRLF normalized to LF."""
    return _packaged(WINDOWS_PATH)


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


def _keyed(row: object, keys: frozenset[str], label: str) -> tuple[dict[str, Any], str]:
    """The row and its sample ID, with the keys and the label checked."""
    if not isinstance(row, dict) or set(row) != keys:
        raise DatasetError(f"{label}: expected an object with exactly the documented keys")
    sample_id = row["sample_id"]
    if not isinstance(sample_id, str) or not sample_id:
        raise DatasetError(f"{label}: sample_id must be a non-empty string")
    if row["label"] not in LABELS:
        raise DatasetError(f"{label}: unknown label")
    return row, sample_id


def _attack_fields(
    row: dict[str, Any], goals: tuple[str, ...], label: str
) -> tuple[str | None, str | None, str | None]:
    """``(category, attack_goal, goal_target)``, consistent with the row's label."""
    category = _optional_str(row, "category", label)
    goal = _optional_str(row, "attack_goal", label)
    target = _optional_str(row, "goal_target", label)
    if row["label"] == "benign":
        if category is not None or goal is not None or target is not None:
            raise DatasetError(f"{label}: a benign sample has no category, goal or target")
        return None, None, None
    if category not in CATEGORIES or goal not in goals:
        raise DatasetError(f"{label}: an injection needs a known category and attack_goal")
    if (target is not None) is not (goal in GOALS_WITH_TARGET):
        raise DatasetError(f"{label}: goal_target is set exactly for goals that need one")
    if goal == "forced_severity" and target not in {s.value for s in Severity}:
        raise DatasetError(f"{label}: a forced_severity target must be a severity")
    return category, goal, target


def parse_row(row: object, number: int) -> Sample:
    label = f"dataset line {number}"
    row, sample_id = _keyed(row, KEYS, label)
    if row["split"] not in SPLITS:
        raise DatasetError(f"{label}: unknown split")
    if row["format"] not in FORMATS:
        raise DatasetError(f"{label}: unknown format")
    if not isinstance(row["hard_negative"], bool):
        raise DatasetError(f"{label}: hard_negative must be a boolean")
    if row["label"] == "injection" and row["hard_negative"]:
        raise DatasetError(f"{label}: only a benign sample can be a hard negative")
    category, goal, target = _attack_fields(row, ATTACK_GOALS, label)
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


def parse_windows_row(row: object, number: int) -> WindowsSample:
    label = f"dataset line {number}"
    row, sample_id = _keyed(row, WINDOWS_KEYS, label)
    category, goal, target = _attack_fields(row, WINDOWS_GOALS, label)
    if row["group"] not in WINDOWS_GROUPS:
        raise DatasetError(f"{label}: unknown group")
    technique = _optional_str(row, "expected_technique", label)
    if row["expected_min_severity"] not in [s.value for s in Severity]:
        raise DatasetError(f"{label}: expected_min_severity must be a severity")
    truth = _optional_str(row, "truth_pattern", label)
    if truth is not None and truth not in TRUTH_PATTERNS:
        raise DatasetError(f"{label}: unknown truth_pattern")
    miss = _optional_str(row, "known_miss", label)
    if miss is not None and (miss not in KNOWN_MISSES or truth is None):
        raise DatasetError(f"{label}: known_miss needs a known blind spot and a truth_pattern")
    if technique is None and (row["label"] != "benign" or truth is not None):
        raise DatasetError(
            f"{label}: a null expected_technique needs a benign sample with no truth_pattern"
        )
    return WindowsSample(
        sample_id=sample_id,
        label=row["label"],
        category=category,
        attack_goal=goal,
        goal_target=target,
        hard_negative=False,
        split=NO_SPLIT,
        format="wazuh",
        alert=_alert("wazuh", row["record"], label),
        group=row["group"],
        expected_technique=technique,
        expected_min_severity=Severity(row["expected_min_severity"]),
        truth_pattern=truth,
        known_miss=miss,
    )


_S = TypeVar("_S", bound=Sample)


def _parse_lines(text: str, parse: Callable[[object, int], _S]) -> list[_S]:
    samples: list[_S] = []
    for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            raise DatasetError(f"dataset line {number}: not valid JSON") from None
        samples.append(parse(row, number))
    ids = [sample.sample_id for sample in samples]
    if len(set(ids)) != len(ids):
        raise DatasetError("sample_id values are not unique")
    if not samples:
        raise DatasetError("the dataset is empty")
    return samples


def parse_dataset(text: str) -> list[Sample]:
    """Every sample in ``text`` (JSONL). Raises ``DatasetError`` on the first problem."""
    return _parse_lines(text, parse_row)


def parse_windows_dataset(text: str) -> list[WindowsSample]:
    """Every Windows-auth sample in ``text`` (JSONL), or ``DatasetError``."""
    return _parse_lines(text, parse_windows_row)


def load_dataset() -> list[Sample]:
    """The packaged main dataset, parsed and checked."""
    return parse_dataset(dataset_text())


def load_windows_dataset() -> list[WindowsSample]:
    """The packaged Windows-auth dataset, parsed and checked."""
    return parse_windows_dataset(windows_dataset_text())
