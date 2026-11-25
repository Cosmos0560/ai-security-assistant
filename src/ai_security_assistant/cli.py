"""Command-line entry point: ``aisa triage <file>``, ``aisa eval`` and ``--version``.

``aisa triage`` runs the full pipeline with EVERY defense on (``DefenseConfig.ALL``): sanitize +
wrap, detector, one provider call per alert (``--provider``, ``--max-calls``) and the validator.
The provider is ``--provider``, else ``LLM_PROVIDER`` (environment, then ``.env`` in the current
directory, ``config.py``), else ``mock``; ``ollama`` runs a health check first and exits 2 with a
clear message if Ollama is down or the model is missing. ``aisa eval`` ignores ``LLM_PROVIDER``.
It writes ``report.md`` and ``report.json`` into ``--out-dir`` (default ``reports/``) and refuses
to overwrite them without ``--force``; ``--include-raw`` adds the raw model replies to
``report.json`` only. There is deliberately no option to weaken the defenses: the ablation
configurations exist only in the Python API (``pipeline.run_pipeline``) for the eval.

The terminal gets only an escaped summary (counts and the two paths), never alert or model text.

``--dry-run`` prints each normalized alert together with its sanitize report and detector
decision as ``ensure_ascii`` JSON, and stops (no provider, no report).

``aisa eval [--out metrics.json] [--readme README.md]`` runs the Phase 6 ablation on the packaged
dataset with the mock providers only (seeded, deterministic, offline). It prints the metrics JSON,
or writes it to ``--out``; ``--readme`` rewrites the generated metrics block of that file.
``--dataset windows`` runs the same mock ablation on the Windows-auth set (D43) and prints its own
document; it has no README block.

``aisa eval --provider {ollama,anthropic} --out FILE`` is the optional LIVE eval
(docs/LIVE_EVAL.md). It is resumable (D44): every alert is written to a checkpoint as soon as it is
done, and the same command continues from there. ``--dataset``, ``--subset``, ``--limit`` and
``--configs`` choose which alerts are sent to the model; ``--retry-errors`` runs again the pairs
that ended in a provider error. Progress and a rough time estimate go to stderr. Next to ``FILE`` it
writes ``<stem>.samples.json``: per sample and configuration, the status, reason codes and booleans
only (no model or alert text). A partial run writes both with ``"complete": false``; complete
results are never overwritten. ``anthropic`` spends real money, so it needs ``AISA_LIVE=1``, a key
and an explicit ``--max-calls``. Both refuse ``--readme`` (the README table is mock-only) and refuse
to run when ``CI`` is set. The gate, the tests and CI never run it with a real provider.

Exit codes (PLAN section 2): 0 every alert triaged; 3 at least one alert needs human review or
hit the call budget (live eval: the run is incomplete); 2 usage, input or provider-setup error, a
report or result that would be overwritten, or a checkpoint of another run; 1 internal error (no
traceback is printed).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from ai_security_assistant import __version__
from ai_security_assistant.config import (
    DOTENV_NAME,
    ConfigError,
    load_settings,
    resolve_provider,
)
from ai_security_assistant.detector.heuristics import detect
from ai_security_assistant.eval.checkpoint import (
    CHECKPOINT_SUFFIX,
    CHECKPOINT_VERSION,
    Checkpoint,
    CheckpointError,
)
from ai_security_assistant.eval.dataset import (
    DATASET_NAMES,
    dataset_sha256,
    dataset_text,
    load_dataset,
    load_windows_dataset,
    windows_dataset_text,
)
from ai_security_assistant.eval.metrics import (
    compute_metrics,
    compute_windows_metrics,
    live_metrics,
    live_samples,
)
from ai_security_assistant.eval.readme_table import MarkerError, render_block, replace_block
from ai_security_assistant.eval.runner import (
    SEED,
    STOPPED_BUDGET,
    STOPPED_INTERRUPTED,
    SUBSETS,
    LiveResult,
    run_eval,
    run_live,
    select_samples,
)
from ai_security_assistant.ingest import FORMATS, IngestError, load_alerts
from ai_security_assistant.ingest.base import safe_repr
from ai_security_assistant.kb import KbError, PatternFact, load_kb, reference_facts
from ai_security_assistant.kb.patterns import batch_patterns
from ai_security_assistant.models import Alert
from ai_security_assistant.pipeline import DefenseConfig, RunResult, run_pipeline
from ai_security_assistant.prompt import NAIVE_PROMPT_VERSION, PROMPT_VERSION
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
# ``aisa eval`` providers: the mocks (the default, offline) or the optional live eval.
EVAL_PROVIDERS = ("mock", "ollama", "anthropic")
LIVE_ENV = "AISA_LIVE"  # required for the paid provider
CI_ENV = "CI"  # the live eval never runs where this is set
# Where ``aisa triage`` looks for ``.env``: the current directory only. Tests replace it.
DOTENV_PATH = Path(DOTENV_NAME)


def utc_now() -> datetime:
    """The report clock. Tests replace it with a fixed value."""
    return datetime.now(UTC)


def monotonic() -> float:
    """The latency clock of the live eval, in seconds. Tests replace it."""
    return time.monotonic()


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


def _positive_int(raw: str) -> int:
    value = _non_negative_int(raw)
    if value == 0:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _config_list(raw: str) -> tuple[DefenseConfig, ...]:
    """``--configs``: a comma list of D22 names, returned in D22 order."""
    names = [name.strip() for name in raw.split(",")]
    known = [config.label for config in DefenseConfig]
    if len(set(names)) != len(names) or not set(names) <= set(known):
        raise argparse.ArgumentTypeError(f"a comma list without repeats from: {', '.join(known)}")
    return tuple(config for config in DefenseConfig if config.label in names)


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
        default=None,
        help="model provider (default: LLM_PROVIDER from the environment or .env, else mock, "
        "which is offline; anthropic needs the extra and the ANTHROPIC_API_KEY environment "
        "variable; ollama needs a local Ollama with the model pulled)",
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
    evaluate = commands.add_parser(
        "eval", help="run the 4-config ablation on the packaged dataset (mock providers only)"
    )
    evaluate.add_argument(
        "--out", type=Path, help="write the metrics JSON here instead of printing it"
    )
    evaluate.add_argument(
        "--dataset",
        choices=DATASET_NAMES,
        default="main",
        help="main (default: the 120-alert set) or windows (the Windows-auth set)",
    )
    evaluate.add_argument(
        "--readme", type=Path, help="rewrite the generated metrics block in this README"
    )
    evaluate.add_argument(
        "--provider",
        choices=EVAL_PROVIDERS,
        default="mock",
        help="mock (default: offline, deterministic, feeds the README), or the optional live eval "
        "with ollama (local) or anthropic (paid: needs AISA_LIVE=1, ANTHROPIC_API_KEY and "
        "--max-calls); a live eval needs --out and never touches the README",
    )
    evaluate.add_argument(
        "--max-calls",
        type=_non_negative_int,
        default=None,
        help="live eval only: most provider calls in THIS invocation, retries included "
        "(required for anthropic; 480 covers 120 alerts x 4 configurations)",
    )
    evaluate.add_argument(
        "--subset",
        choices=SUBSETS,
        default=None,
        help="live eval, main dataset only: all (default), dev or heldout",
    )
    evaluate.add_argument(
        "--limit",
        type=_positive_int,
        default=None,
        help="live eval only: the first N alerts of the fixed stratified order",
    )
    evaluate.add_argument(
        "--configs",
        type=_config_list,
        default=None,
        help="live eval only: comma list of defense configs (default: all four)",
    )
    evaluate.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help=f"live eval only: the resume file (default: <out stem>{CHECKPOINT_SUFFIX}); "
        f"its name must end with {CHECKPOINT_SUFFIX}",
    )
    evaluate.add_argument(
        "--retry-errors",
        action="store_true",
        help="live eval only: run again the pairs that ended in a provider error",
    )
    return parser


def _error(message: str) -> int:
    print(f"aisa: error: {message}", file=sys.stderr)
    return EXIT_INPUT_ERROR


def _dry_run_entry(alert: Alert, pattern: PatternFact | None = None) -> dict[str, object]:
    """The normalized alert plus what the input-side defenses make of it (Phase 3), and the
    trusted reference facts (Phase 9) the model would be given."""
    sanitized, report = sanitize_alert(alert)
    result = detect(sanitized, report)
    facts = reference_facts(alert, pattern)
    return {
        **alert.model_dump(mode="json"),
        "sanitize": report.to_dict(),
        "detector": result.to_dict(),
        "reference_facts": None if facts is None else facts.to_dict(),
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
    try:
        load_kb()  # fail before any alert is touched, like the provider health check
    except KbError as exc:
        return _error(str(exc))
    if args.dry_run:
        patterns = batch_patterns(alerts)
        document = [_dry_run_entry(alert, patterns.get(i)) for i, alert in enumerate(alerts)]
        print(json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False))
        return EXIT_OK
    out_dir: Path = args.out_dir
    if out_dir.exists() and not out_dir.is_dir():
        return _error(f"{safe_repr(str(out_dir), 200)} is not a directory")
    try:
        settings = load_settings(os.environ, DOTENV_PATH)
        provider_name = resolve_provider(args.provider, settings)
    except ConfigError as exc:
        return _error(str(exc))
    budget = CallBudget(args.max_calls)
    try:
        provider = make_provider(provider_name, budget, settings=settings)
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


def metrics_json(metrics: dict[str, object]) -> str:
    """The metrics document as stable, ASCII-only JSON (sorted keys, LF, trailing newline)."""
    return json.dumps(metrics, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"


def _attack_line(metrics: dict[str, object]) -> str:
    totals = metrics["totals"]["full"]  # type: ignore[index]
    success = ", ".join(
        f"{config} {cell['n']}/{cell['of']}" for config, cell in totals["attack_success"].items()
    )
    return f"aisa: eval attack success: {success}"


def samples_path(out: Path) -> Path:
    """Where the live eval writes its per-sample codes: next to ``out``, ``<stem>.samples.json``."""
    return out.with_name(f"{out.stem}.samples.json")


def checkpoint_path(out: Path) -> Path:
    """The default resume file of a live eval writing ``out``."""
    return out.with_name(f"{out.stem}{CHECKPOINT_SUFFIX}")


def _partial_run(path: Path) -> str | None:
    """The ``run_started`` of the PARTIAL result at ``path``, or None for anything else."""
    try:
        document = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(document, dict) or document.get("complete") is not False:
        return None
    started = document.get("run_started")
    return started if isinstance(started, str) else None


def _write_result(path: Path, text: str, run_started: str) -> bool:
    """Write a new file, or replace the partial result of this same run. False if not possible."""
    try:
        if not path.exists():
            with path.open("x", encoding="ascii", newline="\n") as handle:
                handle.write(text)
        elif _partial_run(path) == run_started:
            temporary = path.with_name(f"{path.name}.tmp")
            temporary.write_text(text, encoding="ascii", newline="\n")
            os.replace(temporary, path)
        else:
            return False
    except OSError:
        return False
    return True


def _progress(line: str) -> None:
    # stderr, so that stdout stays clean for results that could not be written.
    print(terminal_safe(line), file=sys.stderr, flush=True)


def _live_guards(args: argparse.Namespace) -> str | None:
    """Why this live eval may not start, or None. Nothing here touches a provider or a file."""
    if os.environ.get(CI_ENV):
        return "the live eval never runs when CI is set"
    paid = args.provider == "anthropic"
    if paid and os.environ.get(LIVE_ENV) != "1":
        return f"the live eval calls a paid API; set {LIVE_ENV}=1 to run it on purpose"
    if args.readme is not None:
        return "the live eval never writes the README; the README table is mock-only"
    if args.out is None:
        return "the live eval needs --out, a separate results file"
    if paid and not args.max_calls:
        return "the live eval needs --max-calls (480 covers 120 alerts x 4 configurations)"
    if args.max_calls == 0:
        return "--max-calls 0 would run nothing"
    if args.dataset == "windows" and args.subset not in (None, "all"):
        return "--subset applies to the main dataset only; the Windows set has no split"
    return None


def _live_paths(args: argparse.Namespace) -> tuple[Path, Path, Path] | str:
    """``(out, samples, checkpoint)``, or why they cannot be used."""
    out: Path = args.out
    samples = samples_path(out)
    checkpoint: Path = args.checkpoint or checkpoint_path(out)
    if not checkpoint.name.endswith(CHECKPOINT_SUFFIX):
        return f"the checkpoint name must end with {CHECKPOINT_SUFFIX}, which git ignores"
    for parent in (out.parent, checkpoint.parent):
        if not parent.is_dir():
            return f"{safe_repr(str(parent), 200)} is not a directory"
    for path in (out, samples):
        if path.exists() and (not checkpoint.exists() or _partial_run(path) is None):
            return f"{safe_repr(str(path), 200)} exists; the live eval never overwrites results"
    return out, samples, checkpoint


def _live_report(result: LiveResult, budget: CallBudget) -> None:
    print(f"aisa: live eval used {budget.used} of {budget.max_calls} calls")
    if result.stopped == STOPPED_BUDGET:
        print("aisa: stopped at the call budget")
    elif result.stopped == STOPPED_INTERRUPTED:
        print("aisa: interrupted; every finished alert is in the checkpoint")
    if result.complete:
        return
    print(
        f"aisa: the results are incomplete: {result.pending} pairs not run, "
        f"{result.errored} ended in a provider error"
    )
    print("aisa: run the same command again to resume")
    if result.errored:
        print("aisa: add --retry-errors to run the errored pairs again")


def _live_eval(args: argparse.Namespace) -> int:
    """The optional live eval (docs/LIVE_EVAL.md). Every guard runs before any model call."""
    problem = _live_guards(args)
    if problem is not None:
        return _error(problem)
    paths = _live_paths(args)
    if isinstance(paths, str):
        return _error(paths)
    out, samples_out, checkpoint_file = paths
    windows = args.dataset == "windows"
    batch = load_windows_dataset() if windows else load_dataset()
    subset = args.subset or "all"
    selected = select_samples(batch, subset=subset, limit=args.limit)
    configs = args.configs or tuple(DefenseConfig)
    budget = CallBudget(args.max_calls or len(selected) * len(configs))
    try:
        provider = make_provider(args.provider, budget)
        kb_version = load_kb().kb_version
    except (ProviderConfigError, KbError) as exc:
        return _error(str(exc))
    sha256 = dataset_sha256(windows_dataset_text() if windows else dataset_text())
    model = str(getattr(provider, "model", provider.name))
    pinned: dict[str, object] = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "dataset": args.dataset,
        "dataset_sha256": sha256,
        "kb_version": kb_version,
        "prompt_version": PROMPT_VERSION,
        "naive_prompt_version": NAIVE_PROMPT_VERSION,
        "seed": SEED,
        "provider": args.provider,
        "model": model,
        "subset": subset,
        "limit": args.limit,
        "configs": [config.label for config in configs],
    }
    try:
        checkpoint = Checkpoint.open(checkpoint_file, pinned, utc_now().isoformat())
        for path in (out, samples_out):
            if path.exists() and _partial_run(path) != checkpoint.started:
                return _error(f"{safe_repr(str(path), 200)} belongs to another run; not touched")
        result = run_live(
            selected,
            batch,
            configs,
            provider,
            checkpoint,
            retry_errors=args.retry_errors,
            clock=monotonic,
            progress=_progress,
        )
    except CheckpointError as exc:
        return _error(str(exc))
    except OSError:
        return _error(f"cannot read or write {safe_repr(str(checkpoint_file), 200)}")
    metrics = live_metrics(result, windows=windows)
    metrics["run_started"] = checkpoint.started
    metrics["live"].update(
        provider=args.provider,
        model=model,
        dataset=args.dataset,
        subset=subset,
        limit=args.limit,
        date=utc_now().date().isoformat(),
    )
    sample_rows = {**live_samples(result, sha256=sha256), "run_started": checkpoint.started}
    documents = ((out, metrics_json(metrics)), (samples_out, metrics_json(sample_rows)))
    unwritten = [
        text for path, text in documents if not _write_result(path, text, checkpoint.started)
    ]
    if unwritten:
        # The calls are already made (and maybe paid for): keep the results on stdout.
        for text in unwritten:
            print(text, end="")
        return _error("cannot write the live eval results; the unwritten ones are on stdout")
    _live_report(result, budget)
    print(_attack_line(metrics))
    print(f"aisa: wrote {terminal_safe(out.as_posix())}")
    print(f"aisa: wrote {terminal_safe(samples_out.as_posix())}")
    return EXIT_OK if result.complete else EXIT_REVIEW


def _eval(args: argparse.Namespace) -> int:
    windows = args.dataset == "windows"
    if args.provider != "mock":
        return _live_eval(args)
    live_only = {
        "--max-calls": args.max_calls,
        "--subset": args.subset,
        "--limit": args.limit,
        "--configs": args.configs,
        "--checkpoint": args.checkpoint,
        "--retry-errors": args.retry_errors or None,
    }
    for flag, value in live_only.items():
        if value is not None:
            return _error(f"{flag} applies to the live eval only (--provider ollama or anthropic)")
    if windows and args.readme is not None:
        return _error("the README metrics block is built from the main dataset only")
    if windows:
        metrics = compute_windows_metrics(run_eval(load_windows_dataset()))
    else:
        metrics = compute_metrics(run_eval(load_dataset()))
    text = metrics_json(metrics)
    try:
        if args.readme is not None:
            readme: Path = args.readme
            updated = replace_block(readme.read_bytes().decode("utf-8"), render_block(metrics))
            readme.write_bytes(updated.encode("utf-8"))
        if args.out is not None:
            out: Path = args.out
            out.write_bytes(text.encode("ascii"))
    except MarkerError as exc:
        return _error(str(exc))
    except (OSError, UnicodeDecodeError):
        return _error("cannot read or write the eval output files")
    if args.out is None:
        print(text, end="")
        return EXIT_OK
    print(_attack_line(metrics))
    print(f"aisa: wrote {terminal_safe(args.out.as_posix())}")
    if args.readme is not None:
        print(f"aisa: rewrote the metrics block in {terminal_safe(args.readme.as_posix())}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in {"triage", "eval"}:
        parser.print_help()
        return EXIT_OK
    try:
        if args.command == "eval":
            return _eval(args)
        return _triage(args, utc_now)
    except Exception:  # fail with a fixed message: no traceback, no untrusted text
        print("aisa: internal error", file=sys.stderr)
        return EXIT_INTERNAL_ERROR
