# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

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

[1.0.0]: https://github.com/Cosmos0560/ai-security-assistant/releases/tag/v1.0.0
