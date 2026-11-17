"""Command-line entry point: ``aisa triage <file>`` and ``--version``.

``--dry-run`` prints each normalized alert together with its sanitize report and detector
decision (Phase 3), still as ``ensure_ascii`` JSON.

Without ``--dry-run`` (Phase 4) each alert goes through sanitize, detector and one provider call
(``--provider``, ``--max-calls``) and the output is a JSON run summary: one status per alert, never
the model's text. The full report with validation waits for Phase 5.

Exit codes: 0 success, 2 usage, input or provider-setup error. Everything printed is JSON with
``ensure_ascii=True``, so a control or bidi character inside an alert field is written as a
``\\uXXXX`` escape and never reaches the terminal raw. Error messages are built the same way (see
``ingest.base.safe_repr``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ai_security_assistant import __version__
from ai_security_assistant.detector.canary import new_canary
from ai_security_assistant.detector.heuristics import detect
from ai_security_assistant.ingest import FORMATS, IngestError, load_alerts
from ai_security_assistant.ingest.base import safe_repr
from ai_security_assistant.models import Alert
from ai_security_assistant.prompt import PROMPT_VERSION, build_system_prompt, build_user_prompt
from ai_security_assistant.providers import PROVIDER_NAMES, CallBudget, Provider, make_provider
from ai_security_assistant.providers.base import ProviderConfigError
from ai_security_assistant.sanitize import sanitize_alert
from ai_security_assistant.triage import triage_alert
from ai_security_assistant.wrap import new_nonce

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
DEFAULT_MAX_CALLS = 20
STATUS_BLOCKED = "blocked_by_detector"


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


def _run_entry(alert: Alert, provider: Provider, system: str, nonce: str) -> dict[str, object]:
    """One alert through sanitize, detector and (unless blocked) one provider call."""
    sanitized, report = sanitize_alert(alert)
    decision = detect(sanitized, report).decision
    entry: dict[str, object] = {"id": alert.id, "detector": decision}
    if decision == "block":
        entry["status"] = STATUS_BLOCKED  # D10: a blocked alert never reaches the model
        return entry
    result = triage_alert(provider, system, build_user_prompt(sanitized, nonce))
    entry["status"] = result.status.value
    if result.reason is not None:
        entry["reason"] = result.reason
    return entry


def _triage(args: argparse.Namespace) -> int:
    try:
        alerts = load_alerts(args.file, args.format)
    except IngestError as exc:
        return _error(f"{safe_repr(str(args.file), 200)}: {exc}")
    if args.dry_run:
        document = [_dry_run_entry(alert) for alert in alerts]
        print(json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False))
        return EXIT_OK
    budget = CallBudget(args.max_calls)
    try:
        provider = make_provider(args.provider, budget)
    except ProviderConfigError as exc:
        return _error(str(exc))
    system = build_system_prompt(new_canary())
    nonce = new_nonce()
    summary = {
        "provider": provider.name,
        "prompt_version": PROMPT_VERSION,
        "alerts": [_run_entry(alert, provider, system, nonce) for alert in alerts],
        "calls": {"used": budget.used, "max": budget.max_calls},
    }
    print(json.dumps(summary, indent=2, ensure_ascii=True, allow_nan=False))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "triage":
        return _triage(args)
    parser.print_help()
    return EXIT_OK
