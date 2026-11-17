"""The report boundary (TB4, D14): ``report.md`` and ``report.json`` for one run.

Both are deterministic: the clock is injected (``generated_at``), alerts keep input order and
the JSON has sorted keys, ``ensure_ascii`` and a ``schema_version``.

Every value that came from an alert file or from the model is untrusted. Before it is written:

* ``normalize_text`` (the sanitizer's NFKC + Cc/Cf/Cs strip) removes ANSI escape introducers,
  other control characters, zero-width and bidi characters, and folds line breaks to one space;
* a per-field length cap applies (the sanitizer's ``[TRUNCATED]`` marker shows a cut).

In ``report.md`` it is then also Markdown-neutralized:

* link and autolink triggers are defanged, so even a renderer that links bare URLs finds none:
  ``://`` becomes ``[:]//``, ``www.`` becomes ``www[.]`` and ``@`` becomes ``[@]``;
* EVERY ASCII punctuation character is backslash-escaped (CommonMark allows that for all of
  them), which neutralizes links, images, raw HTML, entities, emphasis, backticks, table pipes
  and a line-leading ``#``, ``>`` or ``-``.

Raw model text is NEVER written to ``report.md``. ``report.json`` holds it only with
``include_raw`` (off by default), as a JSON string with ``ensure_ascii``. An accepted verdict is
not raw text: with the validator on it passed all eight checks; with the validator off (the
Python-API ablation only) it is what the undefended system accepted, escaped like any other
untrusted value.
"""

from __future__ import annotations

import json
import math
import re
import string
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from ai_security_assistant.pipeline import AcceptedVerdict, AlertOutcome, DetectorSummary, RunResult
from ai_security_assistant.sanitize import TRUNCATION_MARKER, normalize_text

REPORT_SCHEMA_VERSION: Final = "1"
MD_NAME: Final = "report.md"
JSON_NAME: Final = "report.json"

# Length caps per untrusted value, in characters, applied before escaping.
INPUT_CAP: Final = 200
ID_CAP: Final = 128
RULE_CAP: Final = 128
SEVERITY_RAW_CAP: Final = 32
SHORT_CAP: Final = 64  # verdict severity, technique, one action
SUMMARY_CAP: Final = 600
MAX_ACTIONS_SHOWN: Final = 16
RAW_CAP: Final = 65_536  # report.json with include_raw only

_MD_PUNCTUATION: Final = frozenset(string.punctuation)
_WWW_RE: Final = re.compile(r"www\.", re.IGNORECASE)
NONE_TEXT: Final = "(none)"
# TB4 human factor: the summary is the one free-text field the validator cannot judge
# (summary_manipulation, D34), so the analyst is told where it came from every time.
SUMMARY_LABEL: Final = (
    "Summary (model-generated from untrusted data; verify against the alert fields)"
)


class ReportExistsError(Exception):
    """A report file exists and ``force`` was not given."""


@dataclass(frozen=True)
class ReportPaths:
    markdown: Path
    json: Path


# ---------------------------------------------------------------- text helpers


def clean_text(value: str, cap: int) -> str:
    """Control characters stripped, whitespace folded, length capped. Plain text, not escaped."""
    if cap <= len(TRUNCATION_MARKER):
        raise ValueError("cap must be larger than the truncation marker")
    text = normalize_text(value).strip()
    if len(text) > cap:
        text = text[: cap - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER
    return text


def defang(text: str) -> str:
    """Break every link trigger a Markdown renderer or a linkifier looks for."""
    text = text.replace("://", "[:]//").replace("@", "[@]")
    return _WWW_RE.sub(lambda found: found.group(0)[:3] + "[.]", text)


def md_escape(text: str) -> str:
    """Backslash-escape every ASCII punctuation character (CommonMark)."""
    return "".join("\\" + ch if ch in _MD_PUNCTUATION else ch for ch in text)


def md_text(value: str | None, cap: int) -> str:
    """An untrusted value, safe to place anywhere in a Markdown line or a table cell."""
    if value is None:
        return NONE_TEXT
    text = clean_text(value, cap)
    return md_escape(defang(text)) if text else "(empty)"


def _json_text(value: str | None, cap: int) -> str | None:
    return None if value is None else clean_text(value, cap)


def _number(value: float | None) -> float | None:
    return value if value is not None and math.isfinite(value) else None


def format_time(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- JSON


def _detector_json(summary: DetectorSummary | None) -> dict[str, object] | None:
    if summary is None:
        return None
    return {
        "decision": summary.decision,
        "total": summary.total,
        "rule_ids": list(summary.rule_ids),
        "categories": list(summary.categories),
    }


def _actions(verdict: AcceptedVerdict) -> tuple[list[str], int]:
    shown = [clean_text(a, SHORT_CAP) for a in verdict.recommended_actions[:MAX_ACTIONS_SHOWN]]
    return shown, max(0, len(verdict.recommended_actions) - MAX_ACTIONS_SHOWN)


def _verdict_json(verdict: AcceptedVerdict | None) -> dict[str, object] | None:
    if verdict is None:
        return None
    actions, hidden = _actions(verdict)
    return {
        "severity": _json_text(verdict.severity, SHORT_CAP),
        "mitre_technique": _json_text(verdict.mitre_technique, SHORT_CAP),
        "summary": _json_text(verdict.summary, SUMMARY_CAP),
        "recommended_actions": actions,
        "recommended_actions_hidden": hidden,
        "confidence": _number(verdict.confidence),
        "validated": verdict.validated,
        "prose": verdict.prose,
    }


def _alert_json(index: int, outcome: AlertOutcome, include_raw: bool) -> dict[str, object]:
    alert = outcome.alert
    entry: dict[str, object] = {
        "index": index,
        "id": clean_text(alert.id, ID_CAP),
        "source": alert.source,
        "rule_id": clean_text(alert.rule_id, RULE_CAP),
        "source_severity": clean_text(alert.severity_raw, SEVERITY_RAW_CAP),
        "severity_floor": outcome.severity_floor,
        "status": outcome.status.value,
        "reason_codes": list(outcome.reasons),
        "detector": _detector_json(outcome.detector),
        "provider_called": outcome.called_provider,
        "verdict": _verdict_json(outcome.verdict),
    }
    if include_raw:
        raw = outcome.raw_text
        if raw is not None and len(raw) > RAW_CAP:
            raw = raw[: RAW_CAP - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER
        entry["raw_text"] = raw
    return entry


def build_json(
    run: RunResult, *, generated_at: datetime, input_name: str, include_raw: bool = False
) -> dict[str, object]:
    counts: dict[str, int] = {**run.counts(), "total": len(run.outcomes)}
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": format_time(generated_at),
        "input": clean_text(input_name, INPUT_CAP),
        "provider": run.provider,
        "prompt_version": run.prompt_version,
        "defenses": {
            "config": run.config.label,
            "sanitize_wrap": run.config.sanitize_wrap,
            "detector": run.config.detector,
            "validator": run.config.validator,
        },
        "calls": {"used": run.calls_used, "max": run.calls_max},
        "counts": counts,
        "include_raw": include_raw,
        "alerts": [
            _alert_json(index, outcome, include_raw)
            for index, outcome in enumerate(run.outcomes, start=1)
        ],
    }


def render_json(
    run: RunResult, *, generated_at: datetime, input_name: str, include_raw: bool = False
) -> str:
    document = build_json(
        run, generated_at=generated_at, input_name=input_name, include_raw=include_raw
    )
    return json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n"


# ---------------------------------------------------------------- Markdown


def _detector_md(summary: DetectorSummary | None) -> str:
    if summary is None:
        return "off"
    rules = ", ".join(md_text(rule, SHORT_CAP) for rule in summary.rule_ids) or NONE_TEXT
    return f"{md_text(summary.decision, SHORT_CAP)}, score {summary.total:.1f}, rules: {rules}"


def _verdict_md(verdict: AcceptedVerdict | None) -> list[str]:
    if verdict is None:
        return ["- Verdict: none"]
    actions, hidden = _actions(verdict)
    action_text = ", ".join(md_escape(defang(a)) if a else "(empty)" for a in actions) or NONE_TEXT
    if hidden:
        action_text += f" (and {hidden} more)"
    confidence = _number(verdict.confidence)
    if verdict.validated:
        origin = "yes"
    else:
        origin = "no, validator off" + (", prose reply" if verdict.prose else "")
    return [
        "- Verdict:",
        f"  - Severity: {md_text(verdict.severity, SHORT_CAP)}",
        f"  - MITRE technique: {md_text(verdict.mitre_technique, SHORT_CAP)}",
        f"  - Recommended actions: {action_text}",
        f"  - Confidence: {NONE_TEXT if confidence is None else f'{confidence:.2f}'}",
        f"  - {SUMMARY_LABEL}: {md_text(verdict.summary, SUMMARY_CAP)}",
        f"  - Validated: {origin}",
    ]


def _alert_md(index: int, outcome: AlertOutcome) -> list[str]:
    alert = outcome.alert
    floor = outcome.severity_floor
    reasons = ", ".join(md_text(code, SHORT_CAP) for code in outcome.reasons) or NONE_TEXT
    return [
        f"### Alert {index}: {md_text(outcome.status.value, SHORT_CAP)}",
        "",
        f"- Alert ID: {md_text(alert.id, ID_CAP)}",
        f"- Source: {md_text(alert.source, SHORT_CAP)}",
        f"- Rule: {md_text(alert.rule_id, RULE_CAP)}",
        f"- Source severity: {md_text(alert.severity_raw, SEVERITY_RAW_CAP)}"
        f" (floor: {NONE_TEXT if floor is None else md_text(floor, SHORT_CAP)})",
        f"- Reason codes: {reasons}",
        f"- Detector: {_detector_md(outcome.detector)}",
        *_verdict_md(outcome.verdict),
        "",
    ]


def render_markdown(run: RunResult, *, generated_at: datetime, input_name: str) -> str:
    config = run.config
    stages = [
        name
        for name, enabled in (
            ("sanitize + wrap", config.sanitize_wrap),
            ("detector", config.detector),
            ("validator", config.validator),
        )
        if enabled
    ]
    lines = [
        "# AISA triage report",
        "",
        f"- Report schema: {REPORT_SCHEMA_VERSION}",
        f"- Generated: {format_time(generated_at)}",
        f"- Input: {md_text(input_name, INPUT_CAP)}",
        f"- Provider: {md_text(run.provider, SHORT_CAP)}",
        f"- Defenses: {md_text(config.label, SHORT_CAP)}"
        f" ({', '.join(stages) if stages else 'no defense stage'})",
        f"- Prompt version: {md_text(run.prompt_version, SHORT_CAP)}",
        f"- Provider calls: {run.calls_used} of {run.calls_max}",
        "",
        "The assistant only recommends; a human decides. Every value taken from an alert or from "
        "the model is escaped, and raw model text is never shown in this file.",
        "",
        "## Summary",
        "",
        "| Status | Alerts |",
        "| --- | ---: |",
    ]
    for status, count in run.counts().items():
        lines.append(f"| {md_escape(status)} | {count} |")
    lines += [f"| total | {len(run.outcomes)} |", "", "## Alerts", ""]
    if not run.outcomes:
        lines += ["No alerts.", ""]
    for index, outcome in enumerate(run.outcomes, start=1):
        lines += _alert_md(index, outcome)
    return "\n".join(lines).rstrip("\n") + "\n"


# ---------------------------------------------------------------- files


def write_reports(
    run: RunResult,
    out_dir: Path,
    *,
    generated_at: datetime,
    input_name: str,
    include_raw: bool = False,
    force: bool = False,
) -> ReportPaths:
    """Write both reports into ``out_dir`` (LF line endings). Refuses to overwrite without
    ``force``: if either file exists, nothing is written and ``ReportExistsError`` is raised."""
    paths = ReportPaths(markdown=out_dir / MD_NAME, json=out_dir / JSON_NAME)
    markdown = render_markdown(run, generated_at=generated_at, input_name=input_name)
    document = render_json(
        run, generated_at=generated_at, input_name=input_name, include_raw=include_raw
    )
    if not force and (paths.markdown.exists() or paths.json.exists()):
        raise ReportExistsError("report files already exist; use --force to overwrite")
    mode = "w" if force else "x"
    try:
        for path, text in ((paths.markdown, markdown), (paths.json, document)):
            with path.open(mode, encoding="utf-8", newline="\n") as handle:
                handle.write(text)
    except FileExistsError:
        raise ReportExistsError("report files already exist; use --force to overwrite") from None
    return paths
