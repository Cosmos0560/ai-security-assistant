"""Command-line entry point: ``aisa triage --dry-run <file>`` (Phase 2) and ``--version``.

Exit codes: 0 success, 2 usage or input error. ``--dry-run`` prints the normalized alerts as
JSON with ``ensure_ascii=True``, so a control or bidi character inside an alert field is
written as a ``\\uXXXX`` escape and never reaches the terminal raw. Error messages are built
the same way (see ``ingest.base.safe_repr``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ai_security_assistant import __version__
from ai_security_assistant.ingest import FORMATS, IngestError, load_alerts
from ai_security_assistant.ingest.base import safe_repr

EXIT_OK = 0
EXIT_INPUT_ERROR = 2


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
    return parser


def _error(message: str) -> int:
    print(f"aisa: error: {message}", file=sys.stderr)
    return EXIT_INPUT_ERROR


def _triage(args: argparse.Namespace) -> int:
    if not args.dry_run:
        return _error("only --dry-run is available yet; triage itself arrives in a later phase")
    try:
        alerts = load_alerts(args.file, args.format)
    except IngestError as exc:
        return _error(f"{safe_repr(str(args.file), 200)}: {exc}")
    document = [alert.model_dump(mode="json") for alert in alerts]
    print(json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "triage":
        return _triage(args)
    parser.print_help()
    return EXIT_OK
