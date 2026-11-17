"""The report boundary (TB4, D14): escaping, determinism, goldens, raw text and file writing."""

from __future__ import annotations

import json
import re
import string
import unicodedata
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ai_security_assistant import report
from ai_security_assistant.pipeline import (
    AcceptedVerdict,
    AlertOutcome,
    DefenseConfig,
    DetectorSummary,
    RunResult,
    Status,
)
from ai_security_assistant.report import (
    MD_NAME,
    REPORT_SCHEMA_VERSION,
    ReportExistsError,
    clean_text,
    md_text,
    render_json,
    render_markdown,
    write_reports,
)
from ai_security_assistant.sanitize import TRUNCATION_MARKER
from tests import golden_cases

NOW = golden_cases.REPORT_TIME
ALERT = golden_cases.base_alert()
AT = chr(0x40)
ESC = "\x1b[31m"
BIDI = "\u202e"

# One payload per rendering attack. Each must come out inert in every untrusted field.
PAYLOADS = {
    "link": "[x](http://evil.test)",
    "image": "![](http://evil.test/i.png)",
    "autolink": "<http://evil.test>",
    "bare_url": "see https://evil.test/a now",
    "www": "www.evil.test",
    "mail": "ops" + AT + "evil.test",  # built from parts: no email-shaped literal (D30)
    "html": "<script>alert(1)</script>",
    "pipe": "a | b || c",
    "backticks": "``code`` and `x`",
    "heading": "# heading",
    "quote": "> quoted",
    "list": "- item",
    "entity": "&lt;b&gt; &#60;",
    "emphasis": "*bold* _it_ ~~gone~~",
    "ansi": f"{ESC}red\x1b[0m",
    "bidi": f"abc{BIDI}def",
    "newline": "one\n# two\n> three",
}
ALL_PAYLOADS = " ".join(PAYLOADS.values())

DANGEROUS_RAW = ("<script", "](", "<http", "\x1b", BIDI, "\r")


def unescaped_punctuation(text: str) -> list[str]:
    """ASCII punctuation in ``text`` not preceded by a backslash escape."""
    found: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in string.punctuation:
            i += 2
            continue
        if ch in string.punctuation:
            found.append(ch)
        i += 1
    return found


def mask_escapes(text: str) -> str:
    """Every backslash escape pair replaced by a NUL, so only UNESCAPED text can match."""
    return re.sub(r"\\[!-/:-@\[-`{-~]", "\0", text)


def no_controls(text: str) -> bool:
    return not any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in text if ch != "\n")


def unescape(text: str) -> str:
    return re.sub(r"\\([!-/:-@\[-`{-~])", r"\1", text)


# ---------------------------------------------------------------- md_text


@pytest.mark.parametrize("name", list(PAYLOADS))
def test_every_payload_is_neutralized(name: str) -> None:
    out = md_text(PAYLOADS[name], 200)
    assert unescaped_punctuation(out) == []
    for raw in DANGEROUS_RAW:
        assert raw not in mask_escapes(out)
    assert "\n" not in out
    plain = unescape(out)
    assert (
        "://" not in plain
        and "www." not in plain.casefold()
        and "@" not in plain.replace("[@]", "")
    )


@given(st.text(max_size=400))
def test_md_text_is_always_inert(value: str) -> None:
    out = md_text(value, 120)
    if out == "(empty)":  # the report's own placeholder
        return
    assert unescaped_punctuation(out) == []
    assert no_controls(out)
    plain = unescape(out)
    assert "://" not in plain
    assert "www." not in plain.casefold()
    assert "@" not in plain.replace("[@]", "")
    assert len(clean_text(value, 120)) <= 120


def test_md_text_of_none_and_empty() -> None:
    assert md_text(None, 50) == "(none)"
    assert md_text(" \u200b\t ", 50) == "(empty)"


def test_clean_text_caps_with_the_sanitizer_marker() -> None:
    out = clean_text("x" * 500, 100)
    assert len(out) == 100 and out.endswith(TRUNCATION_MARKER)
    assert clean_text("ok", 100) == "ok"
    with pytest.raises(ValueError, match="cap"):
        clean_text("x", len(TRUNCATION_MARKER))


def test_defang_breaks_every_link_trigger() -> None:
    assert report.defang("http://a.test WWW.b.test x" + AT + "c.test") == (
        "http[:]//a.test WWW[.]b.test x[@]c.test"
    )


def test_a_naive_clock_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone"):
        report.format_time(datetime(2026, 1, 1))  # noqa: DTZ001 - the point of the test
    assert report.format_time(datetime(2026, 1, 1, 5, tzinfo=timezone(timedelta(hours=5)))) == (
        "2026-01-01T00:00:00Z"
    )


# ---------------------------------------------------------------- a hostile run


def hostile_run(*, actions: int = 2, value: str = ALL_PAYLOADS) -> RunResult:
    """Every rendered untrusted field holds ``value``. The verdict comes from the validator-off
    path, so its fields are unconstrained model text."""
    alert = ALERT.model_copy(update={"id": value, "rule_id": value, "severity_raw": value})
    verdict = AcceptedVerdict(
        severity=value,
        mitre_technique=value,
        summary=value,
        recommended_actions=tuple([value] * actions),
        confidence=float("nan"),
        validated=False,
    )
    detector = DetectorSummary("flag", 3.5, ("DO-07",), ("direct_override",))
    triaged = AlertOutcome(alert, Status.TRIAGED, verdict, (), detector, True, raw_text=ESC)
    review = AlertOutcome(
        alert, Status.NEEDS_HUMAN_REVIEW, None, ("schema.not_json",), None, True, raw_text="RAW"
    )
    return RunResult(DefenseConfig.NONE, "mock-naive", "1", (triaged, review), 2, 20)


def test_the_hostile_markdown_report_is_inert() -> None:
    md = render_markdown(hostile_run(), generated_at=NOW, input_name=ALL_PAYLOADS)
    plain = render_markdown(hostile_run(value="x"), generated_at=NOW, input_name="x")
    for raw in DANGEROUS_RAW:
        assert raw not in mask_escapes(md)
    for ch in "<>[]`|":  # every one of them is escaped wherever it appears
        assert ch not in md.replace("\\" + ch, "").replace("| ", "").replace(" |", "")
    assert all(ch.isprintable() or ch == "\n" for ch in md)
    # No payload added, removed or started a line: the structure equals the benign render's.
    lines, plain_lines = md.split("\n"), plain.split("\n")
    assert len(lines) == len(plain_lines)
    for line, plain_line in zip(lines, plain_lines, strict=True):
        assert line[:4] == plain_line[:4], line
    for line in lines:
        if line.startswith("| "):
            assert line.count(" | ") == 1 and line.endswith(" |"), line  # two cells, no more
    header = md.split("## Summary", 1)[0]
    input_line = next(line for line in header.split("\n") if line.startswith("- Input: "))
    assert unescaped_punctuation(input_line.removeprefix("- Input: ")) == []


def test_the_hostile_json_report_is_ascii_and_stripped() -> None:
    text = render_json(hostile_run(), generated_at=NOW, input_name=ALL_PAYLOADS)
    assert text.isascii()
    assert "\\u001b" not in text and "\\u202e" not in text
    document = json.loads(text)
    entry = document["alerts"][0]
    assert all(ch.isprintable() for ch in entry["id"])
    assert entry["verdict"]["confidence"] is None  # NaN is not JSON
    assert len(entry["verdict"]["summary"]) <= report.SUMMARY_CAP
    assert "raw_text" not in entry


def test_long_action_lists_are_cut_and_counted() -> None:
    run = hostile_run(actions=report.MAX_ACTIONS_SHOWN + 3)
    md = render_markdown(run, generated_at=NOW, input_name="x")
    assert "(and 3 more)" in md
    verdict = json.loads(render_json(run, generated_at=NOW, input_name="x"))["alerts"][0]["verdict"]
    assert len(verdict["recommended_actions"]) == report.MAX_ACTIONS_SHOWN
    assert verdict["recommended_actions_hidden"] == 3


def test_an_empty_action_renders_as_empty() -> None:
    verdict = AcceptedVerdict("high", "T1110", "s", ("", "monitor"), 0.5, validated=False)
    run = RunResult(
        DefenseConfig.NONE,
        "m",
        "1",
        (AlertOutcome(ALERT, Status.TRIAGED, verdict, (), None, True),),
        1,
        1,
    )
    md = render_markdown(run, generated_at=NOW, input_name="x")
    assert "Recommended actions: (empty), monitor" in md
    assert "- Defenses: none (no defense stage)" in md
    assert "Validated: no, validator off" in md


def test_a_prose_verdict_is_marked() -> None:
    verdict = AcceptedVerdict.permissive("plain words")
    run = RunResult(
        DefenseConfig.DETECTOR_ONLY,
        "m",
        "1",
        (AlertOutcome(ALERT, Status.TRIAGED, verdict, (), None, True),),
        1,
        1,
    )
    md = render_markdown(run, generated_at=NOW, input_name="x")
    assert "Validated: no, validator off, prose reply" in md
    assert "Detector: off" in md


def test_an_empty_run_still_renders() -> None:
    run = RunResult(DefenseConfig.ALL, "mock", "1", (), 0, 20)
    md = render_markdown(run, generated_at=NOW, input_name="empty.json")
    assert "No alerts." in md
    document = json.loads(render_json(run, generated_at=NOW, input_name="empty.json"))
    assert document["counts"] == {
        "triaged": 0,
        "needs_human_review": 0,
        "budget_exhausted": 0,
        "total": 0,
    }


# ---------------------------------------------------------------- raw model text


def test_raw_text_is_never_in_markdown() -> None:
    marker = "QZXV-raw-reply-marker"
    run = golden_cases.report_run("naive")
    outcomes = tuple(
        AlertOutcome(o.alert, o.status, o.verdict, o.reasons, o.detector, o.called_provider, marker)
        for o in run.outcomes
    )
    hostile = RunResult(run.config, run.provider, run.prompt_version, outcomes, 1, 1)
    md = render_markdown(hostile, generated_at=NOW, input_name="x")
    assert marker not in md
    assert marker not in render_json(hostile, generated_at=NOW, input_name="x")
    with_raw = json.loads(render_json(hostile, generated_at=NOW, input_name="x", include_raw=True))
    assert with_raw["include_raw"] is True
    assert {entry["raw_text"] for entry in with_raw["alerts"]} == {marker}


def test_a_rejected_naive_reply_never_reaches_the_markdown() -> None:
    run = golden_cases.report_run("naive")
    md = render_markdown(run, generated_at=NOW, input_name="x")
    rejected = [o for o in run.outcomes if o.status is Status.NEEDS_HUMAN_REVIEW and o.raw_text]
    assert rejected
    for outcome in rejected:
        assert outcome.raw_text is not None
        assert outcome.raw_text not in md
    assert "Sure, in plain text" not in md
    assert "CNRY" not in md and "system prompt" not in md


def test_include_raw_writes_an_escaped_string() -> None:
    raw_run = hostile_run()
    text = render_json(raw_run, generated_at=NOW, input_name="x", include_raw=True)
    assert text.isascii()
    entries = json.loads(text)["alerts"]
    assert [entry["raw_text"] for entry in entries] == [ESC, "RAW"]
    assert "\\u001b[31m" in text


def test_include_raw_caps_a_huge_reply() -> None:
    base = hostile_run()
    big = AlertOutcome(ALERT, Status.NEEDS_HUMAN_REVIEW, None, (), None, True, "y" * 100_000)
    run = RunResult(base.config, base.provider, "1", (big,), 1, 1)
    entry = json.loads(render_json(run, generated_at=NOW, input_name="x", include_raw=True))
    raw = entry["alerts"][0]["raw_text"]
    assert len(raw) == report.RAW_CAP and raw.endswith(TRUNCATION_MARKER)


# ---------------------------------------------------------------- determinism and goldens


@pytest.mark.parametrize(
    "name",
    [
        "report_well_behaved.md",
        "report_well_behaved.json",
        "report_naive.md",
        "report_naive.json",
    ],
)
def test_reports_match_the_golden_files(name: str) -> None:
    expected = (golden_cases.GOLDEN_DIR / name).read_bytes().decode("utf-8")
    assert golden_cases.render_goldens()[name] == expected.replace("\r\n", "\n")


def test_the_json_report_is_sorted_versioned_and_deterministic() -> None:
    run = golden_cases.report_run("well_behaved")
    first = render_json(run, generated_at=NOW, input_name="in.json")
    assert first == render_json(run, generated_at=NOW, input_name="in.json")
    document = json.loads(first)
    assert document["schema_version"] == REPORT_SCHEMA_VERSION
    assert document["generated_at"] == "2026-01-02T03:04:05Z"
    assert document["include_raw"] is False
    assert first == json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    assert document["defenses"] == {
        "config": "all",
        "sanitize_wrap": True,
        "detector": True,
        "validator": True,
    }


def test_the_naive_golden_report_has_no_hostile_verdict() -> None:
    document = json.loads(golden_cases.render_goldens()["report_naive.json"])
    hostile = document["alerts"][len(golden_cases.benign_alerts()) :]
    assert len(hostile) == len(golden_cases.HOSTILE)
    assert {entry["status"] for entry in hostile} == {"needs_human_review"}
    assert all(entry["verdict"] is None for entry in hostile)


# ---------------------------------------------------------------- files


def test_write_reports_writes_lf_files_and_refuses_to_overwrite(tmp_path: Path) -> None:
    run = golden_cases.report_run("well_behaved")
    paths = write_reports(run, tmp_path, generated_at=NOW, input_name="in.json")
    assert paths.markdown == tmp_path / MD_NAME
    for path in (paths.markdown, paths.json):
        assert b"\r" not in path.read_bytes()
    before = paths.json.read_bytes()
    with pytest.raises(ReportExistsError):
        write_reports(run, tmp_path, generated_at=NOW.replace(year=2030), input_name="in.json")
    assert paths.json.read_bytes() == before
    write_reports(run, tmp_path, generated_at=NOW.replace(year=2030), input_name="x", force=True)
    assert b"2030-01-02" in paths.json.read_bytes()


def test_one_existing_file_is_enough_to_refuse(tmp_path: Path) -> None:
    (tmp_path / "report.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ReportExistsError):
        write_reports(
            golden_cases.report_run("well_behaved"), tmp_path, generated_at=NOW, input_name="x"
        )
    assert not (tmp_path / MD_NAME).exists()


def test_a_file_created_during_the_write_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The existence check and the write are separate steps; exclusive mode closes the gap."""
    real_render = report.render_json

    def render_and_race(*args: object, **kwargs: object) -> str:
        (tmp_path / "report.md").write_text("raced", encoding="utf-8")
        return real_render(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(report, "render_json", render_and_race)
    monkeypatch.setattr(Path, "exists", lambda _self: False)
    with pytest.raises(ReportExistsError):
        write_reports(
            golden_cases.report_run("well_behaved"), tmp_path, generated_at=NOW, input_name="x"
        )
    assert (tmp_path / "report.md").read_text(encoding="utf-8") == "raced"


def test_the_clock_is_used_as_given() -> None:
    run = golden_cases.report_run("well_behaved")
    later = datetime(2027, 7, 7, tzinfo=UTC)
    assert "2027-07-07T00:00:00Z" in render_markdown(run, generated_at=later, input_name="x")
