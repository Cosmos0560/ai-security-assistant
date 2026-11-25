"""The optional live eval (``aisa eval --provider anthropic``, docs/LIVE_EVAL.md), WITHOUT a live
call: every guard is checked, and the run itself is exercised with the naive mock standing in for
the real provider. No test here builds an Anthropic client or opens a socket. Resuming, slicing and
the Ollama flow are in ``test_eval_resume.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_security_assistant import cli
from ai_security_assistant.eval.dataset import load_dataset
from ai_security_assistant.eval.runner import select_samples
from ai_security_assistant.pipeline import DefenseConfig
from ai_security_assistant.providers.base import CallBudget, ProviderConfigError
from ai_security_assistant.providers.mock import NaiveMock

ROOT = Path(__file__).resolve().parent.parent
SUBSET = 12  # a small slice of the dataset keeps these tests fast


@pytest.fixture(autouse=True)
def outside_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(cli.CI_ENV, raising=False)  # the live eval refuses under CI


@pytest.fixture
def stand_in(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Live mode switched on, the dataset cut to SUBSET and the provider replaced by the mock."""
    built: list[str] = []
    monkeypatch.setenv(cli.LIVE_ENV, "1")
    monkeypatch.setattr(cli, "load_dataset", lambda: load_dataset()[:SUBSET])

    def fake_provider(name: str, budget: CallBudget) -> NaiveMock:
        built.append(name)
        return NaiveMock(budget)

    monkeypatch.setattr(cli, "make_provider", fake_provider)
    return built


def live(out: Path, *extra: str) -> list[str]:
    return ["eval", "--provider", "anthropic", "--out", str(out), *extra]


@pytest.mark.parametrize("provider", ["anthropic", "ollama"])
def test_the_live_eval_refuses_under_ci(
    provider: str,
    stand_in: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(cli.CI_ENV, "true")
    args = ["eval", "--provider", provider, "--out", str(tmp_path / "m.json"), "--max-calls", "9"]
    assert cli.main(args) == 2
    assert "CI is set" in capsys.readouterr().err
    assert stand_in == [] and list(tmp_path.iterdir()) == []


def test_the_live_eval_needs_the_opt_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(cli.LIVE_ENV, raising=False)
    assert cli.main(live(tmp_path / "m.json", "--max-calls", "480")) == 2
    assert "AISA_LIVE=1" in capsys.readouterr().err
    monkeypatch.setenv(cli.LIVE_ENV, "yes")  # only the exact value "1" counts
    assert cli.main(live(tmp_path / "m.json", "--max-calls", "480")) == 2
    assert not (tmp_path / "m.json").exists()


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--max-calls", "480", "--readme", "README.md"], "never writes the README"),
        (["--max-calls", "0"], "needs --max-calls"),
        ([], "needs --max-calls"),
    ],
)
def test_the_live_eval_guards(
    stand_in: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    message: str,
) -> None:
    assert cli.main(live(tmp_path / "m.json", *args)) == 2
    assert message in capsys.readouterr().err
    assert stand_in == []  # refused before any provider was built
    assert not (tmp_path / "m.json").exists()


def test_the_live_eval_needs_a_results_file(
    stand_in: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["eval", "--provider", "anthropic", "--max-calls", "480"]) == 2
    assert "needs --out" in capsys.readouterr().err
    assert stand_in == []


def test_the_live_eval_never_overwrites(
    stand_in: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "m.json"
    out.write_text("earlier results", encoding="utf-8")
    assert cli.main(live(out, "--max-calls", "480")) == 2
    assert "never overwrites" in capsys.readouterr().err
    assert out.read_text(encoding="utf-8") == "earlier results"
    assert stand_in == []


def test_an_existing_samples_file_is_never_overwritten(
    stand_in: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "m.json"
    samples = tmp_path / "m.samples.json"
    assert cli.samples_path(out) == samples
    samples.write_text("earlier samples", encoding="utf-8")
    assert cli.main(live(out, "--max-calls", "480")) == 2
    assert "never overwrites" in capsys.readouterr().err
    assert samples.read_text(encoding="utf-8") == "earlier samples"
    assert not out.exists()
    assert stand_in == []


def test_a_missing_results_folder_is_refused_before_any_call(
    stand_in: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(live(tmp_path / "no-such-dir" / "m.json", "--max-calls", "480")) == 2
    assert "is not a directory" in capsys.readouterr().err
    assert stand_in == []


def test_a_failed_write_keeps_the_paid_results_on_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "m.json"
    monkeypatch.setenv(cli.LIVE_ENV, "1")
    monkeypatch.setattr(cli, "load_dataset", lambda: load_dataset()[:SUBSET])

    class Racing(NaiveMock):
        def complete(self, system: str, user: str) -> str:
            out.write_text("written by someone else", encoding="utf-8")  # appears mid-run
            return super().complete(system, user)

    def racing_provider(name: str, budget: CallBudget) -> NaiveMock:
        return Racing(budget)

    monkeypatch.setattr(cli, "make_provider", racing_provider)
    assert cli.main(live(out, "--max-calls", str(4 * SUBSET))) == 2
    captured = capsys.readouterr()
    assert "unwritten ones are on stdout" in captured.err
    assert json.loads(captured.out)["dataset"]["alerts"] == SUBSET  # only the metrics were lost
    assert out.read_text(encoding="utf-8") == "written by someone else"
    assert json.loads(cli.samples_path(out).read_text(encoding="ascii"))["configs"]


def test_the_readme_is_never_a_live_target(
    stand_in: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    before = (ROOT / "README.md").read_bytes()
    assert cli.main(live(ROOT / "README.md", "--max-calls", "480")) == 2
    assert (ROOT / "README.md").read_bytes() == before
    assert stand_in == []


def test_max_calls_is_live_only(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["eval", "--max-calls", "10"]) == 2
    assert "live eval only" in capsys.readouterr().err


def test_a_provider_that_cannot_start_is_an_input_error(
    stand_in: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def no_key(name: str, budget: CallBudget) -> NaiveMock:
        raise ProviderConfigError("ANTHROPIC_API_KEY is not set")

    monkeypatch.setattr(cli, "make_provider", no_key)
    assert cli.main(live(tmp_path / "m.json", "--max-calls", "480")) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err
    assert not (tmp_path / "m.json").exists()


def test_a_full_budget_run_writes_the_results(
    stand_in: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "live.json"
    assert cli.main(live(out, "--max-calls", str(4 * SUBSET))) == 0
    assert stand_in == ["anthropic"]
    metrics = json.loads(out.read_text(encoding="ascii"))
    assert metrics["live"]["reuse"] is False  # reuse is the default for ollama only
    assert metrics["live"]["replies_reused"] == 0
    assert metrics["live"]["calls_made"] > metrics["live"]["distinct_prompts"]
    assert metrics["dataset"]["alerts"] == SUBSET
    assert set(metrics["totals"]["full"]["attack_success"]) == {c.label for c in DefenseConfig}
    printed = capsys.readouterr().out
    assert f"of {4 * SUBSET} calls" in printed
    assert "incomplete" not in printed
    samples = json.loads((tmp_path / "live.samples.json").read_text(encoding="ascii"))
    assert "live.samples.json" in printed
    assert set(samples["configs"]) == {c.label for c in DefenseConfig}
    assert all(len(rows) == SUBSET for rows in samples["configs"].values())


def test_a_short_budget_is_reported_as_incomplete(
    stand_in: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "live.json"
    assert cli.main(live(out, "--max-calls", str(SUBSET))) == 3
    assert "results are incomplete" in capsys.readouterr().out
    assert out.is_file()


def test_the_live_selection_of_the_whole_set_is_the_whole_set() -> None:
    samples = load_dataset()
    selected = select_samples(samples)
    assert sorted(s.sample_id for s in selected) == [s.sample_id for s in samples]
