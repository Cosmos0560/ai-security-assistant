"""Recompute the metrics of a FINISHED live run from its checkpoint, with no model call.

    python scripts/recompute_live.py RESULTS.json CHECKPOINT OUT.json

Every saved reply goes through the pipeline again, which refuses if a prompt or a decision differs
from the recorded one. Then the current ``eval/metrics.py`` builds the results, so a corrected or
new metric applies to a run that already happened. RESULTS.json (the run's own results file) only
supplies the run's date. The checkpoint is read through a temporary copy and never changed.
Writes OUT.json and its ``.samples.json`` companion; existing files are never overwritten.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ai_security_assistant.cli import metrics_json, samples_path
from ai_security_assistant.eval.checkpoint import PINNED_FIELDS, Checkpoint, CheckpointError
from ai_security_assistant.eval.dataset import (
    dataset_sha256,
    dataset_text,
    load_dataset,
    load_windows_dataset,
    windows_dataset_text,
)
from ai_security_assistant.eval.metrics import live_metrics, live_samples
from ai_security_assistant.eval.runner import SEED, run_live, select_samples
from ai_security_assistant.pipeline import DefenseConfig


class NoCalls:
    """The provider of a replay: it has the recorded provider's name and can answer nothing."""

    def __init__(self, name: str) -> None:
        self.name = name

    def complete(self, system: str, user: str) -> str:
        raise CheckpointError("the checkpoint does not hold every pair; nothing is ever called")


def recompute(results: Path, checkpoint_file: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(metrics, samples)`` of the finished run in ``checkpoint_file``."""
    original = json.loads(results.read_bytes())
    header = json.loads(checkpoint_file.read_bytes().split(b"\n", 1)[0])
    pinned = {name: header[name] for name in PINNED_FIELDS}
    windows = pinned["dataset"] == "windows"
    sha256 = dataset_sha256(windows_dataset_text() if windows else dataset_text())
    if pinned["dataset_sha256"] != sha256 or pinned["seed"] != SEED:
        raise CheckpointError("the dataset or the seed is not the one this run used")
    batch = load_windows_dataset() if windows else load_dataset()
    selected = select_samples(batch, subset=pinned["subset"], limit=pinned["limit"])
    configs = tuple(DefenseConfig.from_label(label) for label in pinned["configs"])
    with tempfile.TemporaryDirectory() as folder:
        copy = Path(folder) / checkpoint_file.name
        shutil.copyfile(checkpoint_file, copy)
        checkpoint = Checkpoint.open(copy, pinned, header["started"])
        if len(checkpoint.records) != len(selected) * len(configs):
            raise CheckpointError("the run is not finished; resume it with `aisa eval` first")
        result = run_live(
            selected,
            batch,
            configs,
            NoCalls(pinned["provider"]),
            checkpoint,
            reuse=pinned["reuse"],
        )
    metrics = live_metrics(result, windows=windows)
    metrics["run_started"] = checkpoint.started
    metrics["live"].update(
        {name: pinned[name] for name in ("provider", "model", "dataset", "subset", "limit")},
        date=original["live"]["date"],
    )
    samples = {**live_samples(result, sha256=sha256), "run_started": checkpoint.started}
    return metrics, samples


def main(argv: Sequence[str]) -> int:
    if len(argv) != 3:
        print("usage: recompute_live.py RESULTS.json CHECKPOINT OUT.json", file=sys.stderr)
        return 2
    results, checkpoint_file, out = (Path(item) for item in argv)
    targets = (out, samples_path(out))
    if any(path.exists() for path in targets):
        print("recompute: an output file exists; nothing is overwritten", file=sys.stderr)
        return 2
    try:
        documents = recompute(results, checkpoint_file)
        for path, document in zip(targets, documents, strict=True):
            path.write_text(metrics_json(document), encoding="ascii", newline="\n")
    except (CheckpointError, OSError, ValueError, KeyError) as exc:
        print(f"recompute: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
