# Phase reports

One entry per phase, appended at the end of the phase (format in `CLAUDE.md`).

## Phase 1: Scaffold and guardrails

1. Phase 1, scaffold and guardrails: an installable empty package with every guardrail in place (gate, hook, CI, ignore rules, commit attribution off).
2. Created all Phase 1 files and the first commit (7f8b50b); the hook is fail-closed (exit 2 on any error, `|| exit 2` in settings.json) and covers PLAN.md section 7; attribution is disabled with the `attribution` key (found in the Claude Code 2.1.270 settings schema, where the older boolean key is marked deprecated); push and tag are also in permissions.deny.
3. Gate green on Windows (Python 3.13.14) and in WSL (`.venv-wsl`, Python 3.14.4): 215 tests, 100% coverage on src/, ruff, mypy strict, AST ban, scan, graph and hygiene checks all pass.
4. Deviations: owner changed D1 to Python 3.11-3.14 (requires-python `>=3.11`, 3.14 classifier, CI matrix 3.11-3.14, PLAN.md D1 and section 8 updated); added `tests/__init__.py` (needed for `tests.conftest` imports); CLAUDE.md and PLAN.md committed with the scaffold; no README yet, so pyproject has no readme field; host `python` is 3.14 without our dependencies, so `.venv` uses 3.13 and gate commits use the `.venv/Scripts/python` prefix.
5. Next: Phase 2 (alert model and ingest); needs the owner's mini-siem and soc-log-analyzer sample records or repo paths, checked for email-shaped strings before use.

Graphify: used, `graphify extract . --code-only` built graphify-out/ in 7.7 s (172 nodes, 312 edges, 9 communities over 13 code files; `cluster-only --no-label --no-viz` then wrote GRAPH_REPORT.md), 0 LLM tokens and no network; the 4 doc files are not in the graph (code-only); output is git-ignored and scanned clean.

## Phase 2: Alert model and ingest

1. Phase 2, alert model and ingest: three sources (mini-siem, soc-log-analyzer, Wazuh-style JSON) normalize into one strict `Alert`, and `aisa triage --dry-run <file>` prints it.
2. Added `models.py` (strict pydantic v2 `Alert`, UTC timestamps, raw IP strings plus derived parsed IPs, `untrusted_fields()` over `json_schema_extra`), `ingest/{base,mini_siem,soc_log_analyzer,wazuh}.py` (hard limits 10 MiB, 10000 records, 16384 chars per field; NaN/Infinity and deep nesting rejected; soc schema 1.x only; detection that fails or is ambiguous gives exit 2), the dry-run CLI with `ensure_ascii=True`, 5 synthetic fixtures, 3 test files; commit a924864; sources read-only and checked: mini-siem v1.0.0 = 6adc008 (origin github.com/Cosmos0560/mini-siem), soc-log-analyzer v1.0.0 = bf15f92 (origin github.com/Cosmos0560/soc-log-analyzer).
3. Gate green on Windows (Python 3.13.14) and in WSL (`.venv-wsl`, Python 3.14.4): 323 tests, 100% line and branch coverage on src/, ruff, mypy strict, AST ban, scan, graph and hygiene checks all pass.
4. Deviations: added `.graphifyignore`, `README.md` stub and the pyproject `readme` field (owner-approved additions); all source-supplied strings (ids, rule id, raw severity included) are marked untrusted, only `source` and `timestamp` are trusted; a timestamp with no UTC offset is rejected (soc-log-analyzer 0.x stored databases hold naive times); mini-siem has no alert sample files, so its fixture follows the code that writes `mini-siem.alert.v1`; one extra read-only git call (`rev-list -n1 v1.0.0` in each source repo) beyond the three allowed; `triage` without `--dry-run` exits 2 until Phase 4; tests and fixtures are flat under `tests/` and `tests/fixtures/`, not `tests/unit/`.
5. Next: Phase 3 (sanitizer, wrapping, detector); it needs nothing from the owner and should read `untrusted_fields()` instead of keeping its own list, and apply truncation and per-field caps, which ingest deliberately does not do.

Graphify: used, `graphify query` at start (2 queries, 0 LLM tokens) and `graphify update .` at end (code-only, 413 nodes, 947 edges, no network, graph output ignored and scanned clean); files opened in this repo: 10 (PLAN.md, pyproject.toml, cli.py, test_cli.py, conftest.py, .gitignore, phase-reports.md, plus targeted greps of gate.py, test_repo_config.py and the hook) versus about 17 without the graph (all 13 code files plus the docs), a small saving because the repo is small and the graph does not cover the gate and hook internals that I still had to grep.
