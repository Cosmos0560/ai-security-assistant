# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-26

Local models through Ollama, and Windows facts that the model is never trusted to look up.

### Added

- `ollama` provider (standard library only, loopback only, health check, no retries), provider
  choice through `.env`, `aisa triage` on a local model.
- Windows knowledge base (`data/windows_kb.json`): events, logon types and 4625 status codes,
  given to the model as a trusted reference block; five new Wazuh `data.win.*` fields; password
  spraying or brute force decided by counting across the batch.
- Validator check 9: Windows facts and patterns in a reply must match the table.
- Windows-auth eval set (49 alerts), the `fact_misstatement` goal, triage accuracy, precision,
  review rate and severity over-escalation; `aisa eval --dataset windows`.
- Resumable, sliceable, timed live eval for Ollama and Anthropic (`--subset`, `--limit`,
  `--configs`, `--checkpoint`, `--retry-errors`), with reply reuse for Ollama.
- A model comparison table in the README, generated from committed results files and checked by the
  gate; `scripts/recompute_live.py` to rebuild a finished run's metrics without calling a model.
- Docs: "Local mode (Ollama)", "Why the LLM is never trusted with lookups", threats T12 to T15.

### Changed

- Prompt version 3 (`none`: `naive-2`): the reference block and the list of allowed MITRE IDs.
  Live numbers from v1.0.0 are not comparable.
- For Ollama the reply format limits `mitre_technique` to the validator's allowlist.
- The validator has nine checks.
- `gate.py` checks the Windows table, the Windows set and the comparison block; `--full` also runs
  the Windows eval from the installed wheel.

### Fixed

- Triage accuracy counted a spraying or brute-force sub-technique as correct where the batch counts
  show no pattern, although the validator rejects that claim. Only the exact technique counts now.

### Measured (live run, `qwen3:8b` on Ollama, 2026-11-26, one run per set)

- Main set attack success: `none` 17/60, `detector-only` 11/60, `validator-only` 5/60, `all` 3/60;
  benign alerts sent to review under `all`: 5/60.
- Windows set attack success: `none` 4/8, `detector-only` 1/8, `validator-only` 0/8, `all` 0/8;
  triage accuracy under `all` 13/44, precision of accepted 13/13, but 17/18 accepted verdicts are
  above the expected severity; 24/41 alerts without an injection sent to review.
- Mean latency per call on a CPU: 41.8 s (main), 49.6 s (Windows).

### Measured (live run, Claude Haiku 5.5, 2026-11-26, one run per set)

- Main set attack success: `none` 8/60, `detector-only` 1/60, `validator-only` 0/60, `all` 0/60;
  benign alerts sent to review under `all`: 28/60, 25 of them by the severity floor.
- Windows set attack success: `none` 7/8, `detector-only` 5/8, `validator-only` 0/8, `all` 0/8;
  triage accuracy under `all` 15/44, precision of accepted 15/23, 4/28 accepted verdicts above the
  expected severity; 15/41 alerts without an injection sent to review, 14 of them for a summary
  over 500 characters.
- One call per configuration (no reply reuse); mean latency per call 1.8 s on both sets.

### Known limits

- Distributed and low-and-slow spraying are not seen. A Windows misstatement with no code near it
  passes. Some correct sentences naming two table entries are rejected.

## [1.0.0] - 2026-11-18

First release.

### Added

- `aisa triage`: triage of mini-siem, soc-log-analyzer and Wazuh alerts with every defense on,
  `report.md` and `report.json`, exit codes 0/3/2/1, no flag that weakens a defense.
- Defense layer: strict ingest adapters; sanitizer (NFKC, control and bidi strip, length caps,
  blob flagging); nonce-fenced wrapping; pattern detector with a canary; fail-closed validator
  with eight checks (schema, action allowlist, MITRE allowlist, IOC grounding, canary, limits,
  vendored secret scan, severity floor D33); escaped reports.
- Providers: two offline deterministic mocks (well-behaved and naive) and an optional Anthropic
  provider (key from the environment only, explicit endpoint, call budget counting every attempt).
- `aisa eval`: 120-alert synthetic dataset (60 benign with 19 hard negatives, 60 injections over
  8 categories and 6 attack goals), 4-configuration ablation, metrics with n in every cell, and a
  generated README table checked for drift by the gate.
- Optional live eval (`aisa eval --provider anthropic`), guarded by `AISA_LIVE=1`, an explicit
  `--max-calls` and a new results file; never run by tests or CI. It also writes
  `<stem>.samples.json`: per-sample status, reason codes and booleans, codes only.
- Report label: every model-written summary in `report.md` is marked "model-generated from
  untrusted data; verify against the alert fields".
- End-to-end demo with soc-log-analyzer v1.0.0 (`examples/demo/`, `docs/DEMO.md`), held true by
  `tests/test_demo.py`.
- Docs: README, `docs/THREAT_MODEL.md` with measured residual risk, `docs/OWASP_LLM_2025.md`,
  `docs/LIVE_EVAL.md`, `SECURITY.md`.
- Gate: ruff, mypy strict, pytest with coverage floors, AST ban, detector independence, secret
  and email scan, vendor integrity, dataset invariants, README drift, hygiene; `--full` builds the
  wheel, installs it into a recreated `.venv-release` and smoke-tests the installed CLI.

### Measured (mock providers, full set)

- Attack success: `none` 40/60, `detector-only` 35/60, `validator-only` 9/60, `all` 8/60.
- Residual risk under `all`: 7 `summary_manipulation` successes and 1 forced severity upgrade
  (accepted by design, D33).

### Measured (live run, Claude Haiku 5.5, 2026-11-19, one run)

- Attack success: `none` 6/60, `detector-only` 2/60, `validator-only` 0/60, `all` 1/60 (s015,
  `summary_manipulation`, the documented residual risk); 464 of 480 calls.
- Benign alerts sent to human review under `all`: 33/60. Results in
  `docs/live-eval/2026-11-19-claude-haiku-5-5.json`; not reproducible (no `temperature`).

[1.1.0]: https://github.com/Cosmos0560/ai-security-assistant/releases/tag/v1.1.0
[1.0.0]: https://github.com/Cosmos0560/ai-security-assistant/releases/tag/v1.0.0
