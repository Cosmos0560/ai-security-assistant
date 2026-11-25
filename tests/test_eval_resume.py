"""The resumable, sliceable, timed live eval (D44), all offline: ``aisa eval --provider ollama``
runs through the real ``make_provider`` and health check against a fake transport whose replies come
from the naive mock, with a fake clock. Windows codes are only compared, never given a meaning.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ai_security_assistant import cli
from ai_security_assistant.eval import checkpoint as cp
from ai_security_assistant.eval.dataset import (
    Sample,
    load_dataset,
    load_windows_dataset,
)
from ai_security_assistant.eval.metrics import latency_summary
from ai_security_assistant.eval.runner import (
    LiveResult,
    run_live,
    select_samples,
    stratified_order,
)
from ai_security_assistant.kb.patterns import batch_patterns
from ai_security_assistant.pipeline import DefenseConfig, run_pipeline
from ai_security_assistant.providers import ollama
from ai_security_assistant.providers.base import CallBudget, ContextBudgetExceeded, ProviderError
from ai_security_assistant.providers.mock import NaiveMock
from ai_security_assistant.triage import TriageStatus, triage_alert
from ai_security_assistant.validator import validate

LABELS = [config.label for config in DefenseConfig]
NOW = datetime(2026, 11, 25, 22, 0, tzinfo=UTC)


class FakeOllama:
    """``/api/version``, ``/api/tags`` and ``/api/chat``; the naive mock writes the replies. Each
    chat moves a fake clock by a time that depends on the prompt only, so a resumed run measures
    what an uninterrupted one does."""

    def __init__(self) -> None:
        self.now = 0.0
        self.chats: list[tuple[str, str]] = []  # (system, user)
        self.fail: Callable[[str, str], BaseException | None] = lambda _system, _user: None

    def __call__(self, request: urllib.request.Request, _timeout: float) -> bytes:
        url = request.full_url
        if url.endswith("/api/version"):
            return b'{"version": "0.0-fake"}'
        if url.endswith("/api/tags"):
            names = [ollama.DEFAULT_MODEL, "other:1b"]
            return json.dumps({"models": [{"name": name} for name in names]}).encode()
        assert isinstance(request.data, bytes)
        messages = json.loads(request.data)["messages"]
        system, user = (message["content"] for message in messages)
        self.now += 1 + len(user) % 7
        error = self.fail(system, user)
        if error is not None:
            raise error
        self.chats.append((system, user))
        content = NaiveMock(CallBudget(1)).complete(system, user)
        body = {"done": True, "done_reason": "stop", "message": {"content": content}}
        return json.dumps(body).encode()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeOllama:
    server = FakeOllama()
    monkeypatch.delenv(cli.CI_ENV, raising=False)
    monkeypatch.delenv(cli.LIVE_ENV, raising=False)  # ollama needs no opt-in
    monkeypatch.setattr(ollama, "urllib_transport", server)
    monkeypatch.setattr(cli, "monotonic", lambda: server.now)
    monkeypatch.setattr(cli, "utc_now", lambda: NOW)
    return server


def live(out: Path, *extra: str) -> list[str]:
    return ["eval", "--provider", "ollama", "--out", str(out), *extra]


SMALL = ("--dataset", "windows", "--limit", "6")  # 24 pairs


def read(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text(encoding="ascii"))
    return document


def lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def ckpt(out: Path) -> Path:
    return cli.checkpoint_path(out)


def after(count: int, error: BaseException) -> Callable[[str, str], BaseException | None]:
    """Raise ``error`` on the chat after ``count`` successful ones, and on every later one."""
    seen = []

    def fail(_system: str, _user: str) -> BaseException | None:
        seen.append(1)
        return error if len(seen) > count else None

    return fail


def never(_system: str, _user: str) -> BaseException | None:
    return None


# ---------------------------------------------------------------- a whole run


def test_a_complete_run_writes_results_and_a_checkpoint(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "q.json"
    assert cli.main(live(out, *SMALL)) == 0
    metrics = read(out)
    assert metrics["complete"] is True
    section = metrics["live"]
    assert section["provider"] == "ollama" and section["model"] == ollama.DEFAULT_MODEL
    assert section["dataset"] == "windows" and section["limit"] == 6
    assert section["date"] == "2026-11-25" and section["configs"] == LABELS
    assert section["pairs"] == {"selected": 24, "final": 24, "errored": 0, "pending": 0}
    assert metrics["dataset"]["alerts"] == 6
    header, *records = lines(ckpt(out))
    assert header["started"] == metrics["run_started"] == NOW.isoformat()
    assert set(header) == {*cp.PINNED_FIELDS, cp.STARTED}
    assert [(r["config"], r["sample_id"]) for r in records[:4]] == [
        (label, records[0]["sample_id"]) for label in LABELS
    ]  # one alert through every config, then the next
    assert len(records) == 24 and sum(r["kind"] == "reply" for r in records) == len(fake.chats)
    printed = capsys.readouterr()
    assert "of 24 calls" in printed.out and "incomplete" not in printed.out
    assert "6 alerts x 4 configs = 24 pairs; 0 in the checkpoint; 24 to run" in printed.err
    assert re.search(r"\[24/24\] all w\d{3}: \w+ in \d+s; no model calls left", printed.err)
    assert re.search(r"\[1/24\] .*; 23 model calls left, ETA about \d", printed.err)
    assert "ETA unknown until one is measured" in printed.err


def test_the_samples_file_stays_codes_only(fake: FakeOllama, tmp_path: Path) -> None:
    out = tmp_path / "q.json"
    assert cli.main(live(out, *SMALL)) == 0
    document = read(cli.samples_path(out))
    assert document["complete"] is True and set(document["configs"]) == set(LABELS)
    replies = {r["raw_text"] for r in lines(ckpt(out))[1:] if r["raw_text"]}
    assert replies
    summaries = {json.loads(t)["summary"] for t in replies if t.startswith("{")}
    text = cli.samples_path(out).read_text(encoding="ascii") + out.read_text(encoding="ascii")
    assert not any(summary in text for summary in summaries)
    row = document["configs"]["all"][0]
    assert set(row) == {
        "sample_id", "label", "category", "attack_goal", "hard_negative", "split", "status",
        "reasons", "detector", "called_provider", "schema_valid", "goal_reached",
    }  # fmt: skip


def test_the_main_set_gets_rejections_and_reason_codes(fake: FakeOllama, tmp_path: Path) -> None:
    out = tmp_path / "m.json"
    assert cli.main(live(out, "--limit", "4")) == 0
    metrics = read(out)
    assert set(metrics["validator_rejections"]["ablation"]) == {"validator-only", "all"}
    assert set(metrics["reason_codes"]["operational"]) == {"all"}
    assert metrics["totals"]["full"]["alerts"] == 4


# ---------------------------------------------------------------- interrupted and resumed


def uninterrupted(fake: FakeOllama, tmp_path: Path) -> tuple[Any, Any]:
    out = tmp_path / "whole" / "q.json"
    out.parent.mkdir()
    assert cli.main(live(out, *SMALL)) == 0
    return read(out), read(cli.samples_path(out))


def test_a_run_stopped_with_ctrl_c_resumes_to_the_same_results(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    expected = uninterrupted(fake, tmp_path)
    calls = len(fake.chats)
    fake.chats.clear()
    out = tmp_path / "q.json"
    fake.fail = after(5, KeyboardInterrupt())
    assert cli.main(live(out, *SMALL)) == 3
    partial = read(out)
    assert partial["complete"] is False
    assert partial["live"]["pairs"]["pending"] > 0
    assert read(cli.samples_path(out))["complete"] is False
    said = capsys.readouterr().out
    assert "interrupted" in said and "run the same command again" in said
    assert "--retry-errors" not in said
    fake.fail = never
    assert cli.main(live(out, *SMALL)) == 0  # replaces its own partial results
    assert (read(out), read(cli.samples_path(out))) == expected
    assert len(fake.chats) == calls  # nothing was asked twice


def test_a_run_that_crashes_resumes_to_the_same_results(
    fake: FakeOllama,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = uninterrupted(fake, tmp_path)
    out = tmp_path / "q.json"
    written: list[str] = []

    def crash(line: str) -> None:
        written.append(line)
        if len(written) == 8:
            raise RuntimeError("the disk went away")

    monkeypatch.setattr(cli, "_progress", crash)
    assert cli.main(live(out, *SMALL)) == 1
    assert not out.exists() and len(lines(ckpt(out))) == 8  # header + 7 finished pairs
    monkeypatch.setattr(cli, "_progress", lambda _line: None)
    assert cli.main(live(out, *SMALL)) == 0
    assert (read(out), read(cli.samples_path(out))) == expected


def test_an_unfinished_last_line_is_cut_off_and_run_again(fake: FakeOllama, tmp_path: Path) -> None:
    out = tmp_path / "q.json"
    assert cli.main(live(out, *SMALL)) == 0
    whole = ckpt(out).read_bytes()
    metrics = read(out)
    out.unlink()
    cli.samples_path(out).unlink()
    ckpt(out).write_bytes(whole[:-30])  # killed in the middle of the last write
    asked = len(fake.chats)
    assert cli.main(live(out, *SMALL)) == 0
    assert len(fake.chats) == asked + 1
    assert read(out) == metrics and ckpt(out).read_bytes() == whole


def test_the_call_budget_stops_the_sitting_and_the_next_one_continues(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "q.json"
    assert cli.main(live(out, *SMALL, "--max-calls", "3")) == 3
    assert "stopped at the call budget" in capsys.readouterr().out
    assert len(fake.chats) == 3 and read(out)["complete"] is False
    assert all(r["kind"] != "provider_error" for r in lines(ckpt(out))[1:])
    assert cli.main(live(out, *SMALL)) == 0
    assert read(out)["complete"] is True


def test_complete_results_are_never_overwritten(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "q.json"
    assert cli.main(live(out, *SMALL)) == 0
    before = out.read_bytes()
    assert cli.main(live(out, *SMALL)) == 2
    assert "never overwrites" in capsys.readouterr().err
    assert out.read_bytes() == before


def test_partial_results_of_another_run_are_not_touched(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "q.json"
    fake.fail = after(2, KeyboardInterrupt())
    assert cli.main(live(out, *SMALL)) == 3
    other = json.dumps({"complete": False, "run_started": "2026-01-01T00:00:00+00:00"})
    out.write_text(other, encoding="ascii")
    fake.fail = never
    asked = len(fake.chats)
    assert cli.main(live(out, *SMALL)) == 2
    assert "another run" in capsys.readouterr().err
    assert out.read_text(encoding="ascii") == other and len(fake.chats) == asked


def test_a_result_that_cannot_be_written_is_reported(tmp_path: Path) -> None:
    assert not cli._write_result(tmp_path / "no-such-dir" / "m.json", "{}", "now")
    assert cli._write_result(tmp_path / "m.json", "{}", "now")
    assert not cli._write_result(tmp_path / "m.json", "{}", "now")  # not a partial result


# ---------------------------------------------------------------- errors and refusals


def ask_about(word: str, error: BaseException) -> Callable[[str, str], BaseException | None]:
    return lambda _system, user: error if word in user else None


@pytest.mark.parametrize(
    "error",
    [TimeoutError(), urllib.error.HTTPError("u", 500, "boom", None, None)],  # type: ignore[arg-type]
)
def test_an_error_is_recorded_the_run_continues_and_only_the_flag_retries(
    error: BaseException,
    fake: FakeOllama,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "q.json"
    first = select_samples(load_windows_dataset(), limit=6)[0]
    assert first.alert.target_user
    fake.fail = ask_about(first.alert.target_user, error)
    assert cli.main(live(out, *SMALL)) == 3
    metrics = read(out)
    errored = metrics["live"]["pairs"]["errored"]
    assert errored >= 4 and metrics["live"]["pairs"]["pending"] == 0
    assert metrics["complete"] is False
    # An errored pair measured nothing: it is in no denominator.
    assert metrics["totals"]["full"]["alerts"] == 6 - metrics["live"]["provider_errors"]["all"]
    rows = read(cli.samples_path(out))["configs"]["all"]
    failed = [row for row in rows if row["status"] == "provider_error"]
    assert failed and all(row["goal_reached"] is None for row in failed)
    assert "add --retry-errors" in capsys.readouterr().out

    fake.fail = never
    asked = len(fake.chats)
    assert cli.main(live(out, *SMALL)) == 3  # resumed without the flag: nothing is retried
    assert len(fake.chats) == asked
    assert f"{errored} of them errored; 0 to run" in capsys.readouterr().err

    assert cli.main(live(out, *SMALL, "--retry-errors")) == 0
    assert len(fake.chats) == asked + errored
    done = read(out)
    assert done["complete"] is True and done["live"]["pairs"]["errored"] == 0
    assert len(lines(ckpt(out))) == 1 + 24 + errored  # appended, never rewritten


def test_a_context_refusal_is_its_own_final_status(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    samples = load_windows_dataset()
    long = [s for s in samples if s.group == "locale_ru"][1]
    limit = 1 + [s.sample_id for s in select_samples(samples)].index(long.sample_id)
    out = tmp_path / "q.json"
    args = live(out, "--dataset", "windows", "--limit", str(limit), "--configs", "all")
    assert cli.main(args) == 0  # complete: a refusal is final
    metrics = read(out)
    assert metrics["live"]["refused_context_budget"] == {"all": 1}
    assert metrics["live"]["provider_errors"] == {"all": 0}
    assert metrics["live"]["latency_ms"]["all"]["n"] == len(fake.chats)
    (row,) = [
        r for r in read(cli.samples_path(out))["configs"]["all"] if r["sample_id"] == long.sample_id
    ]
    assert row["status"] == "refused_context_budget"
    assert row["reasons"] == ["schema.refused_context_budget"]
    assert row["called_provider"] is False
    (record,) = [r for r in lines(ckpt(out))[1:] if r["sample_id"] == long.sample_id]
    assert record["kind"] == "refused_context_budget" and record["latency_ms"] is None
    out.unlink()
    cli.samples_path(out).unlink()
    asked = len(fake.chats)
    capsys.readouterr()
    assert cli.main([*args, "--retry-errors"]) == 0  # even then a refusal is not retried
    assert len(fake.chats) == asked and read(out) == metrics
    assert "0 to run" in capsys.readouterr().err


def test_the_refusal_has_its_own_error_and_reason_code() -> None:
    class Refuses:
        name = "refuses"

        def complete(self, system: str, user: str) -> str:
            raise ContextBudgetExceeded("too long")

    result = triage_alert(Refuses(), "s", "u")
    assert result.status is TriageStatus.REFUSED_CONTEXT_BUDGET
    assert issubclass(ContextBudgetExceeded, ProviderError)
    alert = load_windows_dataset()[0].alert
    assert "schema.refused_context_budget" in validate(result, alert, "canary").reasons
    run = run_pipeline([alert], Refuses(), CallBudget(1), config=DefenseConfig.NONE)
    assert run.outcomes[0].reasons == ("provider.refused_context_budget",)
    assert not run.outcomes[0].called_provider


def test_a_truncated_reply_is_final_not_an_error(fake: FakeOllama, tmp_path: Path) -> None:
    def truncated(request: urllib.request.Request, timeout: float) -> bytes:
        if request.full_url.endswith("/api/chat"):
            return b'{"done": true, "done_reason": "length", "message": {"content": "{"}}'
        return fake(request, timeout)

    out = tmp_path / "q.json"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ollama, "urllib_transport", truncated)
        assert cli.main(live(out, "--dataset", "windows", "--limit", "2")) == 0
        kinds = {r["kind"] for r in lines(ckpt(out))[1:]}
        assert kinds <= {"malformed", "not_called"} and "malformed" in kinds
        out.unlink()
        cli.samples_path(out).unlink()
        assert cli.main(live(out, "--dataset", "windows", "--limit", "2")) == 0  # replays


# ---------------------------------------------------------------- the checkpoint fails closed


def stopped(fake: FakeOllama, tmp_path: Path, *args: str) -> Path:
    """A run stopped after a few pairs; ``out`` and the samples file are removed again."""
    out = tmp_path / "q.json"
    fake.fail = after(5, KeyboardInterrupt())
    assert cli.main(live(out, *(args or SMALL))) == 3
    fake.fail = never
    out.unlink()
    cli.samples_path(out).unlink()
    return out


def refused(fake: FakeOllama, capsys: pytest.CaptureFixture[str], args: list[str]) -> str:
    """Exit 2 with no model call, no results and an unchanged checkpoint."""
    capsys.readouterr()
    path = ckpt(Path(args[args.index("--out") + 1]))
    before = path.read_bytes()
    asked = len(fake.chats)
    assert cli.main(args) == 2
    assert len(fake.chats) == asked and path.read_bytes() == before
    assert not Path(args[args.index("--out") + 1]).exists()
    return capsys.readouterr().err


@pytest.mark.parametrize("name", cp.PINNED_FIELDS)
def test_a_difference_in_any_pinned_field_refuses_and_names_it(
    name: str, fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = stopped(fake, tmp_path)
    header, rest = ckpt(out).read_bytes().split(b"\n", 1)
    document = json.loads(header)
    document[name] = "something else"
    ckpt(out).write_bytes(json.dumps(document).encode() + b"\n" + rest)
    message = refused(fake, capsys, live(out, *SMALL))
    assert "another run" in message and f"{name} (checkpoint 'something else'" in message
    assert re.findall(r"(\w+) \(checkpoint", message) == [name]


@pytest.mark.parametrize(
    ("args", "field"),
    [
        (["--dataset", "windows", "--limit", "7"], "limit"),
        (["--dataset", "main", "--limit", "6"], "dataset"),
        ([*SMALL, "--configs", "all"], "configs"),
    ],
)
def test_a_different_command_refuses(
    args: list[str],
    field: str,
    fake: FakeOllama,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = stopped(fake, tmp_path)
    assert f"{field} (checkpoint" in refused(fake, capsys, live(out, *args))


def test_a_different_model_refuses(
    fake: FakeOllama,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = stopped(fake, tmp_path)
    monkeypatch.setenv(ollama.ENV_MODEL, "other:1b")
    assert "model (checkpoint" in refused(fake, capsys, live(out, *SMALL))


def test_a_changed_prompt_or_decision_refuses_before_any_call(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = stopped(fake, tmp_path)
    original = ckpt(out).read_bytes()
    records = lines(ckpt(out))
    index = next(i for i, r in enumerate(records) if i and r["kind"] == "reply")

    def rewrite(**changes: Any) -> None:
        changed = [{**r, **changes} if i == index else r for i, r in enumerate(records)]
        ckpt(out).write_bytes("".join(json.dumps(r) + "\n" for r in changed).encode())

    rewrite(prompt_sha256="0" * 64)
    assert "the prompt differs" in refused(fake, capsys, live(out, *SMALL))
    rewrite(status="needs_human_review", reasons=["made.up"])
    assert "decides differently" in refused(fake, capsys, live(out, *SMALL))
    rewrite(kind="not_called", raw_text=None, prompt_sha256=None)
    assert "the prompt differs" in refused(fake, capsys, live(out, *SMALL))
    ckpt(out).write_bytes(original)
    assert cli.main(live(out, *SMALL)) == 0


def test_a_record_outside_the_selection_refuses(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = stopped(fake, tmp_path)
    header, first, *rest = ckpt(out).read_text(encoding="ascii").splitlines()
    stray = json.dumps({**json.loads(first), "sample_id": "w999"})
    ckpt(out).write_text("\n".join([header, first, stray, *rest]) + "\n", encoding="ascii")
    assert "did not select" in refused(fake, capsys, live(out, *SMALL))


@pytest.mark.parametrize(
    ("damage", "message"),
    [
        (lambda data: data.replace(b'{"config"', b'{"konfig"', 1), "line 2 is damaged"),
        (lambda data: data.split(b"\n", 1)[0] + b"\nnot json\n", "line 2 is damaged"),
        (lambda data: b"notes\n" + data, "not a checkpoint"),
        (lambda _data: b"a file with no newline", "not a checkpoint"),
        (lambda _data: b'{"checkpoint_version": "1"}\n', "not a checkpoint"),
    ],
)
def test_a_damaged_checkpoint_refuses(
    damage: Callable[[bytes], bytes],
    message: str,
    fake: FakeOllama,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = stopped(fake, tmp_path)
    ckpt(out).write_bytes(damage(ckpt(out).read_bytes()))
    assert message in refused(fake, capsys, live(out, *SMALL))


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "guess"},
        {"config": 1},
        {"reasons": "none"},
        {"reasons": [1]},
        {"latency_ms": 1.5},
        {"raw_text": None},  # a reply with no text
        {"reason": "truncated"},  # a reason code on a reply
    ],
)
def test_a_record_with_a_wrong_shape_is_damage(changes: dict[str, Any]) -> None:
    good = cp.Record("all", "s001", "reply", None, "triaged", (), "ab", 5, "{}")
    row = json.loads(good.to_json())
    assert cp._record(row) == good
    assert cp._record({**row, **changes}) is None
    assert cp._record([row]) is None


def test_a_missing_header_field_is_a_difference_even_when_null_is_expected(tmp_path: Path) -> None:
    path = tmp_path / "a.checkpoint.jsonl"
    pinned: dict[str, object] = {**dict.fromkeys(cp.PINNED_FIELDS, "x"), "limit": None}
    header = {name: value for name, value in pinned.items() if name != "limit"}
    path.write_text(json.dumps({**header, cp.STARTED: "now"}) + chr(10), encoding="ascii")
    with pytest.raises(cp.CheckpointError, match="limit"):
        cp.Checkpoint.open(path, pinned, "now")


def test_a_long_header_value_is_cut_in_the_message() -> None:
    assert cp._shown("x" * 200).endswith("...") and len(cp._shown("x" * 200)) == 80


def test_the_header_must_pin_every_field(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pin exactly"):
        cp.Checkpoint.open(tmp_path / "a.checkpoint.jsonl", {"model": "m"}, "now")


def test_an_empty_file_starts_a_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "a.checkpoint.jsonl"
    path.write_bytes(b"")
    pinned: dict[str, object] = dict.fromkeys(cp.PINNED_FIELDS, "x")
    assert cp.Checkpoint.open(path, pinned, "now").records == {}
    assert cp.Checkpoint.open(path, pinned, "later").started == "now"


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--checkpoint", "run.jsonl"], "must end with"),
        (["--checkpoint", "no-such-dir/a.checkpoint.jsonl"], "is not a directory"),
        (["--max-calls", "0"], "would run nothing"),
        (["--dataset", "windows", "--subset", "dev"], "main dataset only"),
    ],
)
def test_ollama_guards(
    extra: list[str],
    message: str,
    fake: FakeOllama,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(live(tmp_path / "q.json", *extra)) == 2
    assert message in capsys.readouterr().err
    assert fake.chats == [] and list(tmp_path.iterdir()) == []


def test_a_checkpoint_that_cannot_be_read_is_an_input_error(
    fake: FakeOllama, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = tmp_path / "d.checkpoint.jsonl"
    folder.mkdir()
    assert cli.main(live(tmp_path / "q.json", "--checkpoint", str(folder))) == 2
    assert "cannot read or write" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flag",
    [
        ["--subset", "all"],
        ["--limit", "2"],
        ["--configs", "all"],
        ["--checkpoint", "a.checkpoint.jsonl"],
        ["--retry-errors"],
    ],
)
def test_the_live_flags_do_not_apply_to_the_mock(
    flag: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["eval", *flag]) == 2
    assert "live eval only" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flag", [["--limit", "0"], ["--configs", "all,all"], ["--configs", "everything"]]
)
def test_bad_slicing_values_are_usage_errors(flag: list[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        cli.build_parser().parse_args(["eval", *flag])
    assert stop.value.code == 2


def test_configs_are_read_in_d22_order() -> None:
    parsed = cli.build_parser().parse_args(["eval", "--configs", "all, none"])
    assert parsed.configs == (DefenseConfig.NONE, DefenseConfig.ALL)


def test_the_default_clock_is_monotonic() -> None:
    assert cli.monotonic() <= cli.monotonic()


# ---------------------------------------------------------------- slicing


def ids(samples: Sequence[Sample]) -> list[str]:
    return [sample.sample_id for sample in samples]


@pytest.mark.parametrize("load", [load_dataset, load_windows_dataset])
def test_the_fixed_order_mixes_any_prefix(load: Callable[[], Sequence[Sample]]) -> None:
    samples = load()
    ordered = stratified_order(samples)
    assert sorted(ids(ordered)) == ids(samples) and ids(ordered) == ids(stratified_order(samples))
    assert [s.label for s in ordered[:4]] == ["benign", "injection", "benign", "injection"]


def test_the_documented_selections() -> None:
    main, windows = load_dataset(), load_windows_dataset()
    ten = select_samples(main, limit=10)
    assert sum(s.is_injection for s in ten) == 5
    assert len({s.category for s in ten if s.is_injection}) == 5  # strata take turns
    assert {s.hard_negative for s in ten if not s.is_injection} == {True, False}
    assert ids(select_samples(main, limit=2)) == ids(select_samples(main))[:2]
    for split, size in (("dev", 72), ("heldout", 48)):
        chosen = select_samples(main, subset=split)
        assert len(chosen) == size and {s.split for s in chosen} == {split}
    assert len(select_samples(main, subset="dev", limit=9)) == 9
    assert ids(select_samples(windows, limit=2)) == ["w001", "w042"]
    assert len(select_samples(windows, limit=500)) == 49


def test_configs_select_what_is_run(fake: FakeOllama, tmp_path: Path) -> None:
    out = tmp_path / "q.json"
    assert cli.main(live(out, *SMALL, "--configs", "detector-only,validator-only")) == 0
    metrics = read(out)
    assert set(metrics["totals"]["full"]["attack_success"]) == {"detector-only", "validator-only"}
    # Neither ``none`` nor ``all`` ran, so nothing that needs them is claimed.
    assert metrics["totals"]["full"]["executed_under_none"] == {"n": 0, "of": 0}
    assert metrics["totals"]["full"]["alerts"] == 0
    assert metrics["triage_accuracy"]["operational"]["all"] == {"n": 0, "of": 0}
    assert {r["config"] for r in lines(ckpt(out))[1:]} == {"detector-only", "validator-only"}


class Prompts:
    """A provider that keeps every user prompt it is sent."""

    name = "prompts"

    def __init__(self) -> None:
        self.users: list[str] = []
        self._mock = NaiveMock(CallBudget(10_000))

    def complete(self, system: str, user: str) -> str:
        self.users.append(user)
        return self._mock.complete(system, user)


def run_slice(tmp_path: Path, name: str, selected: Sequence[Sample]) -> tuple[LiveResult, Prompts]:
    pinned: dict[str, object] = dict.fromkeys(cp.PINNED_FIELDS, name)
    book = cp.Checkpoint.open(tmp_path / f"{name}.checkpoint.jsonl", pinned, "now")
    provider = Prompts()
    result = run_live(selected, load_windows_dataset(), list(DefenseConfig), provider, book)
    return result, provider


def test_a_sliced_run_gives_each_alert_the_facts_of_a_full_run(tmp_path: Path) -> None:
    batch = load_windows_dataset()
    full, full_prompts = run_slice(tmp_path, "full", select_samples(batch))
    one_of_a_group = [s for s in batch if s.group == "spraying"][:1]
    for number, selected in enumerate(
        [select_samples(batch, limit=2), select_samples(batch, limit=9), one_of_a_group]
    ):
        part, part_prompts = run_slice(tmp_path, f"part{number}", selected)
        for key, outcome in part.outcomes.items():
            assert outcome.facts == full.outcomes[key].facts, key
            assert part.records[key].prompt_sha256 == full.records[key].prompt_sha256, key
        assert set(part_prompts.users) <= set(full_prompts.users)
        assert part.run.full_set == tuple(batch)
    # The check is not empty: from the slice alone, the group's pattern would be different.
    index = batch.index(one_of_a_group[0])
    alone = batch_patterns([one_of_a_group[0].alert])[0]
    whole = batch_patterns([s.alert for s in batch])[index]
    assert alone.pattern != whole.pattern
    facts = (
        run_slice(tmp_path, "again", one_of_a_group)[0]
        .outcomes["all", one_of_a_group[0].sample_id]
        .facts
    )
    assert facts is not None and facts.pattern == whole


def test_the_pattern_metrics_do_not_depend_on_the_slice(fake: FakeOllama, tmp_path: Path) -> None:
    out = tmp_path / "q.json"
    assert cli.main(live(out, "--dataset", "windows", "--limit", "2")) == 0
    assert read(out)["patterns"]["agreement"] == {"n": 22, "of": 30}


# ---------------------------------------------------------------- latency and ETA


def test_the_latency_summary() -> None:
    assert latency_summary([]) == {"n": 0, "mean_ms": None, "p95_ms": None}
    assert latency_summary([7]) == {"n": 1, "mean_ms": 7, "p95_ms": 7}
    values = [100 * n for n in range(1, 21)]  # nearest rank: the 19th of 20
    assert latency_summary(values[::-1]) == {"n": 20, "mean_ms": 1050, "p95_ms": 1900}
    assert latency_summary([*values, 99_000])["p95_ms"] == 2000


def test_latency_comes_from_the_injected_clock(fake: FakeOllama, tmp_path: Path) -> None:
    out = tmp_path / "q.json"
    assert cli.main(live(out, *SMALL)) == 0
    measured = read(out)["live"]["latency_ms"]
    for label in LABELS:
        values = [
            r["latency_ms"]
            for r in lines(ckpt(out))[1:]
            if r["config"] == label and r["latency_ms"] is not None
        ]
        assert values and all(v in range(1000, 8000, 1000) for v in values)
        assert measured[label] == latency_summary(values)


@pytest.mark.parametrize(
    ("seconds", "text"), [(0.2, "0s"), (45, "45s"), (61, "1m01s"), (3600 * 5 + 120, "5h02m")]
)
def test_durations_read_well(seconds: float, text: str) -> None:
    from ai_security_assistant.eval.runner import _duration

    assert _duration(seconds) == text


def test_the_eta_uses_each_configs_own_mean_and_else_the_overall_one() -> None:
    from ai_security_assistant.eval.runner import _eta

    def record(config: str, milliseconds: int) -> cp.Record:
        return cp.Record(config, "s001", "reply", None, "triaged", (), "ab", milliseconds, "{}")

    records = {("none", "s001"): record("none", 10_000), ("all", "s001"): record("all", 30_000)}
    assert _eta(["none", "all", "all"], records).endswith("ETA about 1m10s")
    assert _eta(["detector-only"], records).endswith("ETA about 20s")  # overall mean
    assert _eta([], records) == "no model calls left"
