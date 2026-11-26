"""The model comparison block (D45): what fills a cell, what is n/a, and the README drift check.

Offline: the inputs are the committed results files, copies of them changed on disk, and the mock
eval. The gate check that runs the module is tested here too."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ai_security_assistant.eval import compare_table
from ai_security_assistant.eval.compare_table import Column, ResultsError, load_results
from ai_security_assistant.eval.readme_table import MarkerError, current_block, replace_block
from ai_security_assistant.providers import anthropic, ollama

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "docs" / "live-eval"
README = ROOT / "README.md"
HAIKU, QWEN = anthropic.DEFAULT_MODEL, ollama.DEFAULT_MODEL
OLD_HAIKU = f"2026-11-19-{HAIKU}.json"
# The files this module reads by name. Later runs may be added to the folder beside them.
LOCAL_RUNS = {name: f"2026-11-26-qwen3-8b-{name}.json" for name in ("main", "windows")}
HAIKU_RUNS = {name: f"2026-11-26-{HAIKU}-{name}.json" for name in ("main", "windows")}


def committed(dataset: str, runs: dict[str, str] = LOCAL_RUNS) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((RESULTS / runs[dataset]).read_bytes())
    return document


def put(folder: Path, name: str, document: object) -> None:
    (folder / name).write_text(json.dumps(document), encoding="ascii")


def changed(dataset: str, change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    document = committed(dataset)
    change(document)
    return document


@pytest.fixture(scope="module")
def mock() -> Column:
    return compare_table.mock_column()


@pytest.fixture
def release(tmp_path: Path) -> Path:
    """The folder as released in 1.1.0: both models on both sets, and the old Haiku run."""
    folder = tmp_path / "results"
    folder.mkdir()
    for name in (*LOCAL_RUNS.values(), *HAIKU_RUNS.values(), OLD_HAIKU):
        (folder / name).write_bytes((RESULTS / name).read_bytes())
    return folder


def rows(block: str) -> dict[str, list[str]]:
    """The summary table: row label to its cells (the first row of a label wins)."""
    found: dict[str, list[str]] = {}
    for line in block.split("\n\n")[0].splitlines()[2:]:
        label, *cells = [part.strip() for part in line.strip("|").split("|")]
        found.setdefault(label, cells)
    return found


# ---------------------------------------------------------------- the committed files


def test_the_committed_results_fill_both_model_columns(release: Path) -> None:
    used, unused = load_results(release)
    assert set(used) == {(model, name) for model in (HAIKU, QWEN) for name in ("main", "windows")}
    assert unused == [(OLD_HAIKU, "prompt version 1; not marked complete")]


def test_the_block_shows_the_committed_numbers_and_names_the_unused_file(release: Path) -> None:
    block = compare_table.build_block(release)
    table = rows(block)
    mock_cell, haiku_cell, qwen_cell = table["Attack success, `all`"]
    for cell, runs in ((haiku_cell, HAIKU_RUNS), (qwen_cell, LOCAL_RUNS)):
        main = committed("main", runs)["totals"]["full"]["attack_success"]["all"]
        assert cell == f"{main['n']}/{main['of']}"
    assert mock_cell == "8/60"
    for label, cells in table.items():
        if not label.startswith("**"):
            assert all(cells) and "n/a" not in cells[1:], label  # both model columns are full
    assert f"**`{HAIKU}` by configuration.**" in block and "no complete results file" not in block
    assert f"`{OLD_HAIKU}` (prompt version 1; not marked complete)" in block


def test_a_model_with_no_results_file_is_named(mock: Column) -> None:
    block = compare_table.render_block([mock, Column(HAIKU, None, None)], [])
    assert rows(block)["Attack success, `all`"] == ["8/60", "n/a"]
    assert f"`{HAIKU}` is `n/a`: no complete results file for it is committed." in block
    assert f"**`{HAIKU}` by configuration.**" not in block


def test_no_cell_is_blank_in_the_per_configuration_tables() -> None:
    block = compare_table.build_block(RESULTS)
    for line in block.splitlines():
        if line.startswith("| Main:") or line.startswith("| Windows:"):
            assert all(part.strip() for part in line.strip("|").split("|")), line


def test_the_readme_block_matches() -> None:
    readme = README.read_bytes().decode("utf-8")
    assert current_block(readme, compare_table.MARKERS) == compare_table.build_block(RESULTS)


# ---------------------------------------------------------------- which files count


@pytest.mark.parametrize(
    ("change", "why"),
    [
        (lambda d: d.update(complete=False), "prompt version 3; not marked complete"),
        (lambda d: d.pop("prompt_versions") and d.update(complete=1), "unknown"),
        (lambda d: d.update(dataset_sha256="0" * 64), "another version of the dataset"),
        (lambda d: d["live"].update(model="other-model"), "not a model and set"),
        (lambda d: d["live"].update(dataset="other"), "not a model and set"),
        (lambda d: d.pop("live"), "not a model and set"),
    ],
)
def test_a_file_that_cannot_count_is_named(
    tmp_path: Path, change: Callable[[dict[str, Any]], None], why: str
) -> None:
    put(tmp_path, "run.json", changed("main", change))
    used, unused = load_results(tmp_path)
    assert used == {}
    ((name, reason),) = unused
    assert name == "run.json" and why in reason


def test_the_latest_complete_run_wins(tmp_path: Path) -> None:
    put(tmp_path, "b.json", changed("main", lambda d: d["live"].update(date="2026-11-01")))
    put(tmp_path, "a.json", changed("main", lambda d: d["live"].update(date="2026-12-01")))
    used, unused = load_results(tmp_path)
    assert used[QWEN, "main"]["live"]["date"] == "2026-12-01"
    assert unused == [("b.json", "a later run replaces it")]


def test_per_sample_files_are_not_inputs(tmp_path: Path) -> None:
    put(tmp_path, "run.samples.json", ["not", "a", "results", "document"])
    assert load_results(tmp_path) == ({}, [])


@pytest.mark.parametrize("text", ["{", "[1, 2]"])
def test_an_unreadable_results_file_is_an_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "bad.json").write_text(text, encoding="ascii")
    with pytest.raises(ResultsError, match="bad.json"):
        load_results(tmp_path)


def test_a_missing_folder_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ResultsError, match="not a directory"):
        load_results(tmp_path / "nowhere")


# ---------------------------------------------------------------- rendering


def test_one_set_only_leaves_the_other_n_a(mock: Column) -> None:
    column = Column(QWEN, committed("main"), None)
    block = compare_table.render_block([mock, column], [])
    table = rows(block)
    assert table["Windows-auth set"] == ["n/a", "n/a"]
    assert table["Triage accuracy, `all`"][1] == "n/a"
    assert table["Run date"] == ["every gate run", "2026-11-26"]
    assert "| Windows: attack success | n/a | n/a | n/a | n/a |" in block
    assert "Results files not used" not in block


def test_a_configuration_that_did_not_run_is_n_a(mock: Column) -> None:
    def only_all(document: dict[str, Any]) -> None:
        document["totals"]["full"]["attack_success"]["none"] = {"n": 0, "of": 0}
        document["live"]["latency_ms_all_calls"] = {"n": 0, "mean_ms": None, "p95_ms": None}

    block = compare_table.render_block([mock, Column(QWEN, changed("main", only_all), None)], [])
    table = rows(block)
    assert table["Attack success, `none`"][1] == "n/a"
    assert table["Main set"] == ["n/a", "n/a"]


def test_two_prompt_versions_are_both_shown(mock: Column) -> None:
    newer = changed("windows", lambda d: d["prompt_versions"].update(all="4"))
    block = compare_table.render_block([Column(QWEN, committed("main"), newer)], [])
    assert rows(block)["Prompt version"] == ["3 (`none`: naive-2), 4 (`none`: naive-2)"]


# ---------------------------------------------------------------- the command and the gate


def readme_with(block: str) -> str:
    return f"intro\n{compare_table.BEGIN_MARKER}\n{block}{compare_table.END_MARKER}\noutro\n"


def test_check_and_write(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    readme = tmp_path / "README.md"
    readme.write_bytes(readme_with("edited by hand\n").replace("\n", "\r\n").encode("utf-8"))
    assert compare_table.main(["--check", str(readme), str(RESULTS)]) == 1
    assert "differs" in capsys.readouterr().out
    assert compare_table.main(["--write", str(readme), str(RESULTS)]) == 0
    assert compare_table.main(["--check", str(readme), str(RESULTS)]) == 0
    assert readme.read_bytes().startswith(b"intro\n")


def test_a_readme_without_the_markers_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("no markers\n", encoding="utf-8")
    assert compare_table.main(["--check", str(readme), str(RESULTS)]) == 2
    assert "MarkerError" in capsys.readouterr().out
    with pytest.raises(MarkerError):
        replace_block("no markers\n", "x\n", compare_table.MARKERS)


def test_the_gate_runs_the_comparison_check(
    gate: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert gate.check_comparison in [check for _name, check in gate.CHECKS]
    seen: list[list[str]] = []

    def fake_run_tool(args: list[str]) -> list[str]:
        seen.append(list(args))
        return []

    monkeypatch.setattr(gate, "run_tool", fake_run_tool)
    assert gate.check_comparison() == []
    (args,) = seen
    assert args[1:4] == ["-m", "ai_security_assistant.eval.compare_table", "--check"]
    assert Path(args[4]) == README and Path(args[5]) == RESULTS


def test_the_release_wheel_must_hold_the_windows_data(gate: ModuleType) -> None:
    for name in ("data/windows_kb.json", "data/eval/windows_auth.jsonl"):
        assert f"{gate.PACKAGE}/{name}" in gate.WHEEL_MUST_CONTAIN
