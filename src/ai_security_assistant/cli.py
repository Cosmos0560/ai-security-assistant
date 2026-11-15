"""Command-line entry point (Phase 1 stub: only ``--version``)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from ai_security_assistant import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisa",
        description="Triage synthetic SOC alerts with an LLM behind an injection defense layer.",
    )
    parser.add_argument("--version", action="version", version=f"aisa {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
