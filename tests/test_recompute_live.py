"""``scripts/recompute_live.py``: the metrics of a finished live run, rebuilt from its checkpoint
with no model call. A stand-in provider answers the first run; nothing is sent anywhere."""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ai_security_assistant.cli import metrics_json
from ai_security_assistant.eval.checkpoint import CHECKPOINT_VERSION, Checkpoint
from ai_security_assistant.eval.dataset import (
    dataset_sha256,
    load_windows_dataset,
    windows_dataset_text,
)
from ai_security_assistant.eval.metrics import live_metrics
from ai_security_assistant.eval.runner import SEED, run_live, select_samples
from ai_security_assistant.kb import load_kb
from ai_security_assistant.pipeline import DefenseConfig
from ai_security_assistant.prompt import NAIVE_PROMPT_VERSION, PROMPT_VERSION
from tests.conftest import load_script

REPLY = json.dumps(
    {
        "severity": "medium",
        "mitre_technique": "T1110",
        "summary": "A failed logon.",
        "recommended_actions": ["investigate"],
        "confidence": 0.5,
    }
)


class Stand:
    name = "ollama"

    def complete(self, system: str, user: str) -> str:
        return REPLY


@pytest.fixture(scope="module")
def script() -> ModuleType:
    return load_script("aisa_recompute_live", "scripts/recompute_live.py")


def finished_run(folder: Path, *, limit: int = 3, **header: Any) -> tuple[Path, Path, Any]:
    """A finished two-config run over ``limit`` alerts: ``(results, checkpoint, metrics)``."""
    batch = load_windows_dataset()
    pinned: dict[str, object] = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "dataset": "windows",
        "dataset_sha256": dataset_sha256(windows_dataset_text()),
        "kb_version": load_kb().kb_version,
        "prompt_version": PROMPT_VERSION,
        "naive_prompt_version": NAIVE_PROMPT_VERSION,
        "seed": SEED,
        "provider": "ollama",
        "model": "stand-in",
        "subset": "all",
        "limit": limit,
        "configs": ["none", "all"],
        "reuse": True,
        **header,
    }
    path = folder / "run.checkpoint.jsonl"
    checkpoint = Checkpoint.open(path, pinned, "2026-01-01T00:00:00+00:00")
    result = run_live(
        select_samples(batch, limit=limit),
        batch,
        (DefenseConfig.NONE, DefenseConfig.ALL),
        Stand(),
        checkpoint,
        reuse=True,
        clock=lambda: 0.0,
    )
    results = folder / "run.json"
    results.write_text('{"live": {"date": "2026-01-02"}}', encoding="ascii")
    return results, path, live_metrics(result, windows=True)


def test_it_rebuilds_the_metrics_and_changes_nothing(script: ModuleType, tmp_path: Path) -> None:
    results, checkpoint, original = finished_run(tmp_path)
    before = checkpoint.read_bytes()
    out = tmp_path / "again.json"
    assert script.main([str(results), str(checkpoint), str(out)]) == 0
    again = json.loads(out.read_bytes())
    live = again.pop("live")
    assert again.pop("run_started") == "2026-01-01T00:00:00+00:00"
    assert (live["date"], live["model"], live["provider"]) == ("2026-01-02", "stand-in", "ollama")
    expected = json.loads(metrics_json(original))
    del expected["live"]
    assert again == expected
    samples = json.loads((tmp_path / "again.samples.json").read_bytes())
    assert samples["complete"] is True and set(samples["configs"]) == {"none", "all"}
    assert checkpoint.read_bytes() == before
    assert b"\r" not in out.read_bytes()


def test_it_never_overwrites(
    script: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results, checkpoint, _metrics = finished_run(tmp_path)
    assert script.main([str(results), str(checkpoint), str(results)]) == 2
    assert "nothing is overwritten" in capsys.readouterr().err


def test_an_unfinished_run_is_refused(
    script: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results, checkpoint, _metrics = finished_run(tmp_path)
    lines = checkpoint.read_bytes().splitlines(keepends=True)
    checkpoint.write_bytes(b"".join(lines[:-1]))
    assert script.main([str(results), str(checkpoint), str(tmp_path / "out.json")]) == 2
    assert "not finished" in capsys.readouterr().err
    assert not (tmp_path / "out.json").exists()


def test_another_dataset_is_refused(
    script: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results, checkpoint, _metrics = finished_run(tmp_path)
    text = checkpoint.read_bytes().replace(
        dataset_sha256(windows_dataset_text()).encode("ascii"), b"0" * 64
    )
    checkpoint.write_bytes(text)
    assert script.main([str(results), str(checkpoint), str(tmp_path / "out.json")]) == 2
    assert "not the one this run used" in capsys.readouterr().err


def test_a_replay_can_call_nothing(script: ModuleType) -> None:
    with pytest.raises(script.CheckpointError, match="nothing is ever called"):
        script.NoCalls("ollama").complete("system", "user")


def test_usage(script: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    assert script.main([]) == 2
    assert "usage" in capsys.readouterr().err
