"""Command-line entry point: ``aisa triage <file>`` and ``--version``.

``aisa triage`` runs the full pipeline with EVERY defense on (``DefenseConfig.ALL``): sanitize +
wrap, detector, one provider call per alert (``--provider``, ``--max-calls``) and the validator.
It writes ``report.md`` and ``report.json`` into ``--out-dir`` (default ``reports/``) and refuses
to overwrite them without ``--force``; ``--include-raw`` adds the raw model replies to
``report.json`` only. There is deliberately no option to weaken the defenses: the ablation
configurations exist only in the Python API (``pipeline.run_pipeline``) for the eval.

The terminal gets only an escaped summary (counts and the two paths), never alert or model text.

``--dry-run`` prints each normalized alert together with its sanitize report and detector
decision as ``ensure_ascii`` JSON, and stops (no provider, no report).

Exit codes (PLAN section 2): 0 every alert triaged; 3 at least one alert needs human review or
hit the call budget; 2 usage, input or provider-setup error, or a report that would be
overwritten; 1 internal error (no traceback is printed).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from ai_security_assistant import __version__
from ai_security_assistant.detector.heuristics import detect
from ai_security_assistant.ingest import FORMATS, IngestError, load_alerts
from ai_security_assistant.ingest.base import safe_repr
from ai_security_assistant.models import Alert
from ai_security_assistant.pipeline import DefenseConfig, RunResult, run_pipeline
from ai_security_assistant.providers import PROVIDER_NAMES, CallBudget, make_provider
from ai_security_assistant.providers.base import ProviderConfigError
from ai_security_assistant.report import ReportExistsError, ReportPaths, write_reports
from ai_security_assistant.sanitize import sanitize_alert

EXIT_OK = 0
EXIT_INTERNAL_ERROR = 1
EXIT_INPUT_ERROR = 2
EXIT_REVIEW = 3
DEFAULT_MAX_CALLS = 20
DEFAULT_OUT_DIR = Path("reports")
# The only configuration the CLI runs. Not an option: there is no flag that changes it.
CLI_DEFENSES = DefenseConfig.ALL


def utc_now() -> datetime:
    """The report clock. Tests replace it with a fixed value."""
    return datetime.now(UTC)


def terminal_safe(text: str) -> str:
    """Printable ASCII only: anything else becomes its Python escape (for example ``\\x1b``)."""
    return "".join(ch if " " <= ch <= "~" else ascii(ch)[1:-1] for ch in text)


def _non_negative_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None
    if value < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisa",
        description="Triage synthetic SOC alerts with an LLM behind an injection defense layer.",
    )
    parser.add_argument("--version", action="version", version=f"aisa {__version__}")
    commands = parser.add_subparsers(dest="command")
    triage = commands.add_parser("triage", help="triage the alerts in a file")
    triage.add_argument("file", type=Path, help="alert file (JSON document or JSONL)")
    triage.add_argument(
        "--format",
        choices=FORMATS,
        default=None,
        help="input format (default: detect; exit 2 if detection fails or is ambiguous)",
    )
    triage.add_argument(
        "--dry-run",
        action="store_true",
        help="print the normalized alerts as JSON and stop (no triage, no LLM)",
    )
    triage.add_argument(
        "--provider",
        choices=PROVIDER_NAMES,
        default="mock",
        help="model provider (default: mock, which is offline; anthropic needs the extra and "
        "the ANTHROPIC_API_KEY environment variable)",
    )
    triage.add_argument(
        "--max-calls",
        type=_non_negative_int,
        default=DEFAULT_MAX_CALLS,
        help=f"most provider calls in this run, retries included (default: {DEFAULT_MAX_CALLS}); "
        "alerts beyond it get the status budget_exhausted",
    )
    triage.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help=f"directory for report.md and report.json (default: {DEFAULT_OUT_DIR.as_posix()}/)",
    )
    triage.add_argument(
        "--include-raw",
        action="store_true",
        help="also write each raw model reply into report.json (never into report.md)",
    )
    triage.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing report files",
    )
    return parser


def _error(message: str) -> int:
    print(f"aisa: error: {message}", file=sys.stderr)
    return EXIT_INPUT_ERROR


def _dry_run_entry(alert: Alert) -> dict[str, object]:
    """The normalized alert plus what the input-side defenses make of it (Phase 3)."""
    sanitized, report = sanitize_alert(alert)
    result = detect(sanitized, report)
    return {
        **alert.model_dump(mode="json"),
        "sanitize": report.to_dict(),
        "detector": result.to_dict(),
    }


def _summary(run: RunResult, paths: ReportPaths) -> str:
    counts = run.counts()
    parts = ", ".join(f"{count} {status}" for status, count in counts.items())
    lines = [
        f"aisa: {len(run.outcomes)} alerts: {parts}",
        f"aisa: wrote {terminal_safe(paths.markdown.as_posix())}",
        f"aisa: wrote {terminal_safe(paths.json.as_posix())}",
    ]
    return "\n".join(lines)


def _triage(args: argparse.Namespace, clock: Callable[[], datetime]) -> int:
    try:
        alerts = load_alerts(args.file, args.format)
    except IngestError as exc:
        return _error(f"{safe_repr(str(args.file), 200)}: {exc}")
    if args.dry_run:
        document = [_dry_run_entry(alert) for alert in alerts]
        print(json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False))
        return EXIT_OK
    out_dir: Path = args.out_dir
    if out_dir.exists() and not out_dir.is_dir():
        return _error(f"{safe_repr(str(out_dir), 200)} is not a directory")
    budget = CallBudget(args.max_calls)
    try:
        provider = make_provider(args.provider, budget)
    except ProviderConfigError as exc:
        return _error(str(exc))
    run = run_pipeline(alerts, provider, budget, config=CLI_DEFENSES)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        paths = write_reports(
            run,
            out_dir,
            generated_at=clock(),
            input_name=args.file.name,
            include_raw=args.include_raw,
            force=args.force,
        )
    except ReportExistsError as exc:
        return _error(str(exc))
    except OSError:
        return _error(f"cannot write the reports into {safe_repr(str(out_dir), 200)}")
    print(_summary(run, paths))
    return EXIT_OK if run.all_triaged else EXIT_REVIEW


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "triage":
        parser.print_help()
        return EXIT_OK
    try:
        return _triage(args, utc_now)
    except Exception:  # fail with a fixed message: no traceback, no untrusted text
        print("aisa: internal error", file=sys.stderr)
        return EXIT_INTERNAL_ERROR
