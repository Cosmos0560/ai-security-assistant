"""The optional live eval (``aisa eval --provider anthropic``, docs/LIVE_EVAL.md), WITHOUT a live
call: every guard is checked, and the run itself is exercised with the naive mock standing in for
the real provider. No test here builds an Anthropic client or opens a socket.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_security_assistant import cli
from ai_security_assistant.eval.dataset import load_dataset
from ai_security_assistant.eval.runner import SEED, run_eval, run_live_eval
from ai_security_assistant.pipeline import DefenseConfig, Status
from ai_security_assistant.providers.base import CallBudget, ProviderConfigError
from ai_security_assistant.providers.mock import NaiveMock

ROOT = Path(__file__).resolve().parent.parent
SUBSET = 12  # a small slice of the dataset keeps these tests fast


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

    def racing_provider(name: str, budget: CallBudget) -> NaiveMock:
        out.write_text("written by someone else", encoding="utf-8")  # appears mid-run
        return NaiveMock(budget)

    monkeypatch.setattr(cli, "make_provider", racing_provider)
    assert cli.main(live(out, "--max-calls", str(4 * SUBSET))) == 2
    captured = capsys.readouterr()
    assert "metrics are on stdout" in captured.err
    assert json.loads(captured.out)["dataset"]["alerts"] == SUBSET
    assert out.read_text(encoding="utf-8") == "written by someone else"


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
    assert metrics["dataset"]["alerts"] == SUBSET
    assert set(metrics["totals"]["full"]["attack_success"]) == {c.label for c in DefenseConfig}
    printed = capsys.readouterr().out
    assert f"of {4 * SUBSET} calls" in printed
    assert "incomplete" not in printed


def test_a_short_budget_is_reported_as_incomplete(
    stand_in: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "live.json"
    assert cli.main(live(out, "--max-calls", str(SUBSET))) == 3
    assert "results are incomplete" in capsys.readouterr().out
    assert out.is_file()


def test_the_live_runner_shares_one_budget_and_one_provider() -> None:
    samples = load_dataset()[:SUBSET]
    budget = CallBudget(4 * SUBSET)
    run = run_live_eval(samples, NaiveMock(budget), budget)
    assert [r.config for r in run.naive] == list(DefenseConfig)
    assert run.well_behaved_all is run.naive_run(DefenseConfig.ALL)
    assert budget.used <= 4 * SUBSET
    # With the naive mock standing in, the per-config outcomes equal the mock-only eval's.
    mock_run = run_eval(samples, SEED)
    for live_cfg, mock_cfg in zip(run.naive, mock_run.naive, strict=True):
        assert [o.status for o in live_cfg.outcomes] == [o.status for o in mock_cfg.outcomes]
    assert all(o.status is not Status.BUDGET_EXHAUSTED for r in run.naive for o in r.outcomes)
