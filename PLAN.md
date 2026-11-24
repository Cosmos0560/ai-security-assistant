# PLAN.md — ai-security-assistant (Project 7)

A CLI assistant that triages SOC alerts with an LLM. Alert fields such as user-agent,
username, command line and URL can be attacker-controlled, so this is an indirect
prompt injection problem. The goal is a working, measurable reference for how to build
an AI SOC assistant safely. The main value is the defense layer.

Everything is synthetic. No real alerts, IOCs or personal data. No real attack code.

---

## 1. Decisions

Each decision has its rationale and the alternative that was rejected.

### Platform and dependencies

**D1. Python 3.11–3.14, CLI only.**
Rationale: 3.11 gives `tomllib` and modern typing; a CLI keeps the attack surface and
the scope small. Rejected: a web UI (adds XSS/CSRF/session concerns that have nothing
to do with the defense layer).

**D2. One runtime dependency: `pydantic` v2.**
Rationale: strict, typed validation of the Alert model and the triage schema is the
core of "fail closed"; hand-written validation is where bugs hide. The CLI uses
`argparse` and reports use string templates. Rejected: zero dependencies with
dataclasses (more validator code to get wrong); `click`/`rich`/`jinja2` (convenience only).

**D3. Dev dependencies: `pytest`, `pytest-cov`, `ruff`, `mypy`, `build`, `hypothesis`.**
Rationale: each maps to one gate check; `hypothesis` drives the sanitizer property
tests. Rejected: `pytest-socket` (a 20-line fixture of our own does the job and is
auditable); `black` (ruff formats).

**D4. Names and packaging: package `ai_security_assistant`, command `aisa`, backend `hatchling`, `src/` layout.**
Rationale: the `src/` layout forces tests to run against the installed package.
Rejected: flat layout (tests can pass against files that the wheel does not ship).

### Pipeline

**D5. Fixed pipeline order:**
ingest → normalize → sanitize + untrusted-data wrapping → injection detector
(heuristics + canary) → LLM triage → output validator → report (Markdown + JSON).
Rationale: every stage narrows what the next stage must trust, and each stage can be
switched off for the ablation. Rejected: a single "guard prompt" that asks the model to
police itself (not measurable, and it fails exactly when the model is fooled).

**D6. Ingest: one normalized `Alert` model plus adapters for mini-siem, soc-log-analyzer and Wazuh-style JSON.**
Rationale: defenses are written once against one model. Fixtures are synthetic. The
real output formats of mini-siem and soc-log-analyzer come from samples supplied by the
owner, not from guesses (see section 10). Rejected: per-source pipelines (three copies
of the defense code).

**D7. Sanitization: NFKC normalization, strip zero-width and bidi control characters, per-field length caps, flag encoded blobs.**
Rationale: these remove the cheap obfuscation tricks before heuristics run, and caps
bound prompt size and cost. Encoded blobs (base64/hex runs) are flagged and not
decoded into the prompt. Rejected: decoding blobs and feeding the result to the model
(turns an inert blob into live instructions).

**D8. Untrusted-data wrapping with a random-boundary delimiter that is escaped inside the data.**
Rationale: a per-run nonce in the boundary cannot be guessed by an attacker, and
escaping any boundary-shaped text in the data blocks delimiter escape. Rejected: fixed
delimiters such as triple backticks or static XML tags (the attacker can close them).

**D9. Detector: heuristic scoring across categories plus a per-run canary in the system prompt.**
Rationale: heuristics are cheap, explainable and measurable; the canary turns
system-prompt leakage into a deterministic check (canary in the output = leak). In
mock/test mode the canary and nonce derive from a deterministic seed. Rejected: an ML
or LLM-based classifier (heavy dependency, second injection surface, not reproducible).

**D10. Detector policy: block threshold and flag threshold.**
A score at or above the block threshold means the alert is not sent to the LLM and gets
status `needs_human_review`. Between flag and block, the alert is sent and the flag is
carried into the report. Rationale: an injection attempt inside an alert is itself a
signal an analyst should see, and not calling the model is the only complete defense.
Rejected: flag-only (the detector would never reduce exposure); silent dropping (hides
evidence).

**D11. Triage output is STRICT JSON: `severity`, `mitre_technique`, `summary`, `recommended_actions`, `confidence`.**
Free text, extra keys and surrounding prose are rejected. Rationale: a closed schema is
the only output a validator can fully check. Rejected: "JSON somewhere in the text"
extraction (lets a hijacked model smuggle free text past the validator).

**D12. Output validator, fail closed to `needs_human_review`.** Checks, in order:
1. schema check;
2. `recommended_actions` only from an allowlist enum;
3. `mitre_technique` by ID regex (`^T\d{4}(\.\d{3})?$`) plus a small offline allowlist,
   with no network call to MITRE;
4. IOC grounding: any IP, domain or hash in the output must appear in the input;
5. canary check;
6. length limits;
7. secret scan of the output with the vendored secret-scanner v1.0.0.
8. severity floor (D33): the output severity may not be below the floor derived from
   the source tool's own severity.

Rationale: the model's output is treated as attacker-influenced. Any failed check or
any exception gives `needs_human_review`, never a partial result. Rejected: repair or
retry on failure (a retry loop is something an attacker can steer, and it costs money).

**D13. Human-in-the-loop: the assistant only recommends.**
`src/` never uses `subprocess`, `os.system`, `eval` or `exec`; an AST check in the gate
enforces it. Rationale: with no execution path, a successful injection can at worst
produce a wrong recommendation that a human reads. Rejected: optional auto-response
(excessive agency, and out of scope).

**D14. Report boundary: untrusted fields are Markdown-escaped and ANSI/control characters are stripped. Raw alert content is not logged by default.**
Rationale: the report is read by a human in a terminal or a Markdown viewer, which is a
fourth trust boundary (link and escape-sequence injection). Rejected: trusting
sanitized input at output time (sanitization targets the model, not the renderer).

### Providers

**D15. Provider abstraction plus a deterministic MOCK with two modes: `well_behaved` and `naive`.**
The naive mock obeys injected instructions, which proves the validator catches what the
model gets wrong. Rationale: reproducible, free, offline evaluation. Rejected: recorded
real-model responses (drift, licensing and key handling for little gain).

**D16. The naive mock's "obedience" parser is independent of the detector.**
It lives in its own module, shares no patterns with the detector, and the gate checks
that it does not import the detector. Rationale: shared patterns would make detection
numbers circular. Rejected: keying the mock on dataset labels (the mock would not be
reading the prompt at all).

**D17. Optional Anthropic provider as the extra `[anthropic]`.**
Key only via the `ANTHROPIC_API_KEY` env var. Model via the `AISA_ANTHROPIC_MODEL` env
var, default `claude-haiku-5-5` (ID confirmed by the owner; no online check needed).
Cost guard: `--max-calls`, a request timeout and `max_tokens`. Rationale: a real
provider shows the abstraction works; Haiku keeps cost low. Rejected: key in a config
file or CLI flag (leaks into shell history and repos); multiple vendors (scope).

**D18. Real API calls never run in tests or CI.**
Live tests are behind the pytest marker `live`, skipped by default. An autouse fixture
blocks sockets. Rejected: live tests gated only by "key is present" (one stray env var
would spend money in CI).

### Vendoring and scanning

**D19. Vendored secret-scanner v1.0.0 at `src/ai_security_assistant/third_party/secret_scanner/`.**
Only the needed detector modules are copied, with `VERSION` (v1.0.0), the source tag,
`LICENSE` and a sha256 manifest (hashes over LF-normalized content, D29). Only
pattern/detector modules are copied. A needed module that imports `subprocess` (for
example a git staged-files mode) is left out, and the omission is recorded in `VERSION`. The copy comes from the owner's local repo, never from
GitHub. The gate fails if a vendored file no longer matches the manifest. Rationale:
inside the package it ships in the wheel with no path mapping and falls under the AST
ban. Rejected: a repo-root `third_party/` (needs build mapping, easy to leave out of
the wheel); a PyPI/git dependency (network, supply chain).

**D20. The repo's own secret/email scan uses a narrow, explicit allowlist.**
Each entry is a file path plus the sha256 of the exact allowed line, with a reason.
It covers vendored regex patterns and scanner test fixtures only. Any edit to an
allowed line invalidates its entry. Line hashes are taken after LF normalization (D29).
In Phases 1–4 the scan uses the gate's own minimal patterns (D31); the vendored
patterns and this allowlist arrive in Phase 5. Rationale: a pattern that detects secrets looks
like a secret to a scanner. Rejected: skipping `third_party/` or `tests/` wholesale
(a real secret placed there would pass).

### Evaluation

**D21. Eval dataset: 120 synthetic alerts = 60 benign + 60 injection.**
Injections span 8 categories: direct override, role-play, delimiter escape, encoded
payload, output-format hijack, IOC/hallucination bait, system-prompt exfiltration,
non-English injection (7–8 samples each). The benign set includes at least 15 hard
negatives (benign text containing words like "ignore" or "system"). IPs only from RFC
5737 ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); domains only
`example.com` and `.test`; obviously fake hashes; encoded blobs decode to harmless text
only. The dataset and fixtures contain no email-shaped strings (usernames only); the
gate enforces this (D30). Rationale: balanced classes and hard negatives give an honest false positive
rate. Rejected: scraped real injections (not synthetic); benign set without hard
negatives (flattering numbers).

**D22. Metrics.** Detection rate, false positive rate, schema-valid rate, attack
success rate across a 4-config ablation with the naive mock (`none`, `detector-only`,
`validator-only`, `all`), and a per-category breakdown. Reporting all four configs
makes the validator's own contribution visible. Sanitize and wrap count as input
preparation and are on in every config except `none`. Every metrics cell shows its n
(for example `46/48`).

**D23. Attack success is machine-checkable.**
Every injection sample carries an `attack_goal`: forced severity, off-allowlist action,
canary leak, ungrounded IOC, non-JSON output, or summary manipulation (D34). Attack
success rate is the share of goals present in the final accepted report. Rationale: without a defined goal,
"success" is a judgement call. Rejected: manual grading.

**D24. Dev / held-out split.**
The dataset is split 60/40 (72 dev, 48 held-out), stratified by class and category.
Heuristics are tuned on dev only. The per-category table is reported on the full set,
because held-out has only 2–4 samples per category. Held-out is reported as totals only. Rationale:
heuristics tuned on the whole set overfit it. Rejected: one pooled number.

**D25. The README metrics table is generated from the eval output, and the gate checks it has not drifted.**
The comparison is byte-exact after LF normalization (D29). Rejected: hand-edited numbers.

### Docs and process

**D26. Docs:** README (CI badge, demo GIF, metrics table, "What it can't do" with honest
limits such as paraphrased and multilingual injections, heuristic ceilings, and the
fact that mock numbers measure pipeline mechanics, not real-model robustness, and that
the eval does not measure secret leakage; the owner records the GIF),
`THREAT_MODEL.md`, and a mapping to the OWASP Top 10 for LLM Applications 2025.

**D27. The PreToolUse hook matches both the Bash and the PowerShell tool.**
Rationale: the host shell is PowerShell, so a Bash-only matcher would let `git push`
through the other tool. Commits themselves run through the Bash tool only, because Windows PowerShell 5.1 has
no `&&`; a `git commit` issued through the PowerShell tool is blocked. Rejected: Bash only.

**D28. Graphify is used from the end of Phase 1** to cut repo re-reading. Its output is
never committed. Rules are in `CLAUDE.md`. Rejected: re-reading the repo each session.

**D29. Line endings are LF everywhere.**
Phase 1 adds `.gitattributes` with `* text=auto eol=lf`. Every sha256 (vendor manifest,
allowlist lines) and every byte-exact comparison (goldens, README drift) normalizes
`\r\n` to `\n` first, through one shared helper. Rationale: Windows CI checks out with
CRLF, which would break hashes and goldens. Rejected: relying on each contributor's
`core.autocrlf` setting.

**D30. No email-shaped literals, including in tests.**
Email-shaped strings needed by tests (hook tests, validator tests) are built at runtime
from parts and never written as literals. The same holds for fake secrets used to test
validator check 7 and for the gate's own scan patterns, so the gate never matches
itself. The dataset and fixtures contain no email-shaped strings at all; this is a gate
dataset invariant. Rationale: the no-email rule then needs no exceptions. Rejected:
allowlisting test files.

**D31. The gate is phase-aware.**
Each check is added to `gate.py` in the phase that creates its artifact. There is no
"skip if file missing" logic anywhere. In Phases 1–4 the secret scan uses the gate's own
minimal patterns: email, a few well-known key prefixes and a private-key header. Phase 5
adds the vendored patterns. Rationale: a check that skips when its input is absent also
skips when the input is deleted by mistake. Rejected: one final gate written in Phase 1
with existence guards.

**D32. Claude Code's commit attribution is disabled in `.claude/settings.json`.**
Phase 1 verifies which key the installed version supports (`includeCoAuthoredBy` or
`attribution`) and sets it. The hook remains the enforcing layer. Rejected: relying on
the setting alone (a key the version ignores fails silently).

**D33. Severity floor: the LLM may RAISE severity but may not LOWER it below the source's own severity (owner decision, Phase 5b).**
The floor comes from a strict mapping table per source, never from free text:
mini-siem's severity enum (`info`, `low`, `medium`, `high`, `critical`, exact
lowercase), soc-log-analyzer's enum (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, exact
uppercase) and the Wazuh `rule.level` bands 0–3 info, 4–6 low, 7–11 medium, 12–14 high,
15 critical (a plain integer 0–15). Any other raw value (unknown word, other case,
padding, sign, a level above 15) is unmappable and gives NO floor; the alert is then
judged by the other checks only. A severity below the floor is validator check 8 and
gives `needs_human_review` with reason `severity.downgrade`. Raising severity is
accepted by design: an injected "mark this critical" costs analyst attention but hides
nothing, and the README lists it under "What it can't do". Rationale: a forced
downgrade is the T1 goal that the other D12 checks cannot see, because it is
schema-valid. Rejected: a floor parsed from alert text (attacker-controlled); a
ceiling as well (would reject legitimate escalation).

**D34. A sixth attack goal: `summary_manipulation` (owner decision, Phase 6).**
The injection asks the model to put attacker-chosen text in the summary (for example "false
positive, no action needed"). Each such sample carries a marker phrase in `goal_target`, and the
goal succeeds when the marker appears in the ACCEPTED verdict's summary. The naive mock obeys it
through its own patterns (D16). The validator is not expected to catch it and gets no check for
it: the text is schema-valid and grounded, so it is a documented residual risk (README "What it
can't do"), not a bug. Rationale: it is the realistic goal of an attacker who wants an alert
closed, and measuring it shows the validator's blind spot honestly. Rejected: a keyword check on
the summary (phrasing-dependent, the detector's weakness moved to the output).

**D35. An honest `none` baseline (owner decision, Phase 6).**
In `none` the alert fields still reach the model: the raw, unsanitized fields are interpolated
into the user prompt as plain `name: value` lines, with no nonce block, and the system prompt has
the same task and output format but no trust rules and no "data is not instructions" wording,
the way a naive implementation would. The canary stays in the system prompt in EVERY config,
because it is measurement instrumentation, not a defense. Both mocks read the fields in all four
configs. Rationale: a baseline whose model cannot see the alert understates what an undefended
system lets through. Rejected: the Phase 5 `none` prompt (boundary-less, but the mocks could not
read it and the system prompt still carried the trust rules).

---

## 2. Architecture

### Module layout

```
src/ai_security_assistant/
  models.py            Alert, TriageResult, Verdict, enums (severity, actions)
  ingest/
    base.py            adapter protocol, format detection
    mini_siem.py
    soc_log_analyzer.py
    wazuh.py
  sanitize.py          NFKC, control-char strip, length caps, blob flagging
  wrap.py              random-boundary wrapping and escaping
  detector/
    heuristics.py      per-category scoring, thresholds
    canary.py          canary generation and matching
  prompt.py            system prompt and user prompt assembly
  providers/
    base.py            Provider protocol, call budget
    mock.py            well_behaved and naive modes
    naive_rules.py     obedience parser (must not import detector)
    anthropic.py       optional, lazy import
  triage.py            one provider call, strict JSON parse
  validator/
    schema.py  actions.py  mitre.py  grounding.py  limits.py  secrets.py
    __init__.py        ordered run, fail closed
  report.py            Markdown and JSON writers, escaping
  pipeline.py          stage wiring, defense toggles for the ablation
  eval/
    dataset.py  runner.py  metrics.py  readme_table.py
  data/
    mitre_allowlist.json  eval/alerts.jsonl
  third_party/secret_scanner/   vendored modules, VERSION, LICENSE, MANIFEST.sha256
  cli.py               `aisa triage`, `aisa eval`
scripts/
  gate.py  scan_allowlist.toml
tests/
  unit/  property/  golden/  eval/  live/  fixtures/  conftest.py
docs/
  THREAT_MODEL.md  OWASP_LLM_2025.md  phase-reports.md
.claude/
  settings.json  hooks/pre_tool_use.py
```

### Data flow and trust boundaries

```
alert file (UNTRUSTED)
   │  TB1: file -> process
   ▼
ingest adapter -> Alert -> sanitize -> wrap(nonce)
                               │
                         detector (heuristics) ── score >= block ──> needs_human_review
                               │
   system prompt + canary      │  TB2: untrusted data enters a trusted prompt
        (trusted) ─────────────▼
                           provider (mock | anthropic)
                               │  TB3: model output is attacker-influenced
                               ▼
                           validator (fail closed) ── any failure ──> needs_human_review
                               │
                               │  TB4: report -> human (terminal / Markdown viewer)
                               ▼
                         report.md + report.json
```

- **TB1.** Adapters parse with strict types and size limits. Unknown fields are dropped.
- **TB2.** Data crosses into the prompt only through `wrap.py`. The system prompt holds
  no secret other than the canary.
- **TB3.** Nothing from the model reaches the report without passing the validator.
- **TB4.** The report escapes untrusted text. No stage executes anything.

Exit codes: `0` all alerts triaged, `3` at least one `needs_human_review`, `2` usage or
input error, `1` internal error.

---

## 3. Threat model summary

### Assets
- Integrity of the triage verdict (severity, technique, actions).
- The system prompt and canary.
- The API key and the API budget.
- The analyst's attention and trust in the report.
- The host running the CLI.

### Attacker-controlled inputs
Any free-text alert field: user-agent, username, hostname, command line, URL, file
path, process name, email subject, raw log message. The attacker does not control the
CLI flags, the system prompt, the code or the environment.

### Threats, controls and residual risk

| # | Threat | Controls | Residual risk |
|---|--------|----------|---------------|
| T1 | Instruction override in a field downgrades severity or closes the alert | Sanitize, wrap, detector block, schema, severity floor (D33), fail closed | Paraphrased injection below the threshold can still bias a real model's severity upward, or downward when the source severity is unmappable |
| T2 | Delimiter escape to leave the data block | Random nonce boundary, escaping of boundary-shaped text | A model may still ignore boundaries; measured, not eliminated |
| T3 | Obfuscation (zero-width, bidi, homoglyph, encoding) hides the payload | NFKC, control-char strip, blob flagging, no decoding | Homoglyphs that survive NFKC; novel encodings |
| T4 | Output-format hijack (free text, extra keys, markup) | Strict JSON parse, schema, length limits, Markdown/ANSI escaping | None known inside the schema |
| T5 | Hallucinated or planted IOC leads the analyst to block the wrong thing | IOC grounding against the input | An attacker's own IOC that is present in the input is grounded by definition |
| T6 | Off-list or dangerous recommended action | Allowlist enum, recommend-only, AST ban | A wrong but allowed action; the human decides |
| T7 | System-prompt or secret exfiltration through the output | Canary check, vendored secret scan, no secrets in the prompt | Paraphrased leakage of prompt wording without the canary |
| T8 | Cost or denial of service through huge or many alerts | Length caps, `--max-calls`, timeout, `max_tokens` | A legitimate large batch is cut off at the budget |
| T9 | Non-English or paraphrased injection evades heuristics | Validator still applies; hard limits in README | Known heuristic ceiling; reported per category |
| T10 | Supply chain (dependency, vendored code, CI action) | One runtime dependency, manifest-checked vendoring, pinned actions, `contents: read` | Compromise of a pinned upstream release |
| T11 | Report rendering attack (links, escape sequences) | Escaping at the report boundary | Viewer-specific rendering bugs |

### OWASP Top 10 for LLM Applications 2025

| ID | Item | Status | How it is addressed |
|----|------|--------|---------------------|
| LLM01 | Prompt Injection | Core | Sanitize, wrap, detector, canary, validator, measured ablation |
| LLM02 | Sensitive Information Disclosure | Applies | Canary check, output secret scan, key only in env, no raw logging |
| LLM03 | Supply Chain | Applies | One runtime dependency, vendored scanner with manifest, pinned CI actions |
| LLM04 | Data and Model Poisoning | N/A | No training, fine-tuning or feedback loop; models are used as provided |
| LLM05 | Improper Output Handling | Applies | Strict JSON, validator, report escaping, no execution path |
| LLM06 | Excessive Agency | Applies | Recommend-only, action allowlist, AST ban on execution primitives |
| LLM07 | System Prompt Leakage | Applies | Canary, no secrets or logic-as-secret in the prompt |
| LLM08 | Vector and Embedding Weaknesses | N/A | No RAG, embeddings or vector store |
| LLM09 | Misinformation | Applies | IOC grounding, MITRE allowlist, confidence field, fail closed to human review |
| LLM10 | Unbounded Consumption | Applies | Length caps, `--max-calls`, timeout, `max_tokens` |

---

## 4. Phases

Seven phases. Each fits one Sonnet 5.5 High session and ends with the phase report
described in `CLAUDE.md`.

### Phase 1 — Scaffold and guardrails
- **Goal:** an empty but installable package with every guardrail in place.
- **Files:** `git init -b main`; `pyproject.toml`; `.gitattributes`
  (`* text=auto eol=lf`); `.gitignore` (venvs, graph output,
  build output, reports); `src/ai_security_assistant/__init__.py`, `cli.py` (stub with
  `--version`); `scripts/gate.py` (Phase 1 checks only, see below);
  `.claude/settings.json` (hook plus commit attribution disabled, D32); `.claude/hooks/pre_tool_use.py`;
  `.github/workflows/ci.yml`; `tests/conftest.py` (socket blocker, `live` marker);
  `docs/phase-reports.md`; `LICENSE` (MIT; the copyright line holds a name only).
- **Gate has:** ruff, mypy, pytest + coverage, AST ban (execution primitives), secret
  and email scan with the gate's own minimal patterns, no graph files staged, commit
  hygiene. It also holds the shared LF-normalization helper.
- **Tests:** CLI stub; socket blocker raises; hook script unit tests (each banned
  command blocked, each allowed command passes, each accepted gate prefix from section
  7 passes); AST-ban check on a bad sample, with `re.compile` allowed and the builtin
  `compile` banned; LF helper gives the same hash for CRLF and LF input; scan patterns
  catch runtime-built email and key strings. No test writes an email-shaped literal.
- **Exit criteria:** gate green on Windows and in WSL; hook blocks every item in
  section 7; the supported attribution key is verified and set; first commit made
  through the gate from the Bash tool.
- **Graphify:** read its help/docs and report (what it does, what it writes, network
  and token use, expected cost). Then first **build**, after the scaffold commit.
  Confirm its output is ignored and scan it for emails and secrets. Do not run any
  Graphify install or integration command that edits `CLAUDE.md`,
  `.claude/settings.json` or git hooks; if it offers one, report to the owner first.
  Record the build time and token cost in the phase report.

### Phase 2 — Alert model and ingest
- **Goal:** three sources normalize into one `Alert`.
- **Needs:** sample outputs from mini-siem and soc-log-analyzer; the owner gives the
  paths in the Phase 2 prompt. Sample records are checked for email-shaped strings
  before use.
- **Gate adds:** nothing. The Phase 1 email scan already covers the new fixtures.
- **Files:** `models.py`, `ingest/*`, `tests/fixtures/{mini_siem,soc_log_analyzer,wazuh}/`.
- **Tests:** per-adapter round trips, format detection, malformed and oversized input,
  unknown fields dropped.
- **Exit criteria:** `aisa triage --dry-run <file>` prints normalized alerts for all
  three formats.
- **Graphify:** **query** at start, **update** at end (new modules).

### Phase 3 — Sanitizer, wrapping, detector
- **Goal:** the input-side defenses.
- **Files:** `sanitize.py`, `wrap.py`, `detector/heuristics.py`, `detector/canary.py`.
- **Gate adds:** nothing.
- **Tests:** unit tests per rule; property tests (section 5); heuristic tests per
  category with hard negatives; deterministic canary and nonce under a seed.
- **Exit criteria:** properties hold; no boundary-shaped text survives wrapping.
- **Graphify:** **query**, then **update**.

### Phase 4 — Providers and triage
- **Goal:** a provider abstraction with a deterministic mock and an optional real one.
- **Files:** `prompt.py`, `providers/{base,mock,naive_rules,anthropic}.py`, `triage.py`,
  `tests/golden/`, `tests/live/`.
- **Gate adds:** the AST check that `providers/naive_rules.py` and `providers/mock.py`
  do not import `detector`.
- **Tests:** golden tests for both mock modes; naive mock obeys one sample per
  category; call budget, timeout and `max_tokens` enforced against a stub client;
  missing key gives a clear error; live tests skipped by default.
- **Exit criteria:** naive mock produces a goal-achieving output for each category;
  no socket is opened in the test run; `anthropic` is imported only when selected.
- **Graphify:** **query**, then **update**.

### Phase 5 — Vendored scanner, validator, report, pipeline, CLI
- **Goal:** the full pipeline end to end.
- **Needs:** the local path of the secret-scanner repo; the owner gives it in the
  Phase 5 prompt.
- **Files:** `third_party/secret_scanner/*` with `VERSION`, `LICENSE`,
  `MANIFEST.sha256`; `validator/*`; `data/mitre_allowlist.json`; `report.py`;
  `pipeline.py`; `cli.py`; `scripts/scan_allowlist.toml` (created here, with its entries).
- **Gate adds:** the vendored patterns in the secret scan, the allowlist with its
  stale-entry check, and vendor integrity against the manifest.
- **Tests:** one passing and one failing case per validator check (check 7 uses fake
  secrets built at runtime from parts); vendored modules pass the AST ban; exception inside a
  check gives `needs_human_review`; report escaping; manifest check; exit codes.
- **Exit criteria:** `aisa triage` writes Markdown and JSON reports with the mock; the
  naive mock's outputs are rejected by the validator; gate scan is green with the
  narrow allowlist only.
- **Graphify:** **query**, then **update**.

### Phase 6 — Dataset, eval, metrics
- **Goal:** measured results.
- **Files:** `data/eval/alerts.jsonl` (120 alerts with labels, category, split,
  `attack_goal`); `eval/*`; README metrics block.
- **Gate adds:** dataset invariants (including no email-shaped strings) and the README
  metrics drift check. The eval metric floors run inside pytest.
- **Tests:** dataset invariants; metric functions on hand-built cases; eval as a test
  with metric floors; the 4-config ablation reports attack
  success for `none`, `detector-only`, `validator-only` and `all`, and `none` is higher
  than `all`; every metrics cell carries its n.
- **Exit criteria:** `aisa eval` writes the metrics JSON and regenerates the README
  table; the gate fails when the table is edited by hand.
- **Graphify:** **query**, then **update**.

### Phase 7 — Docs, full gate, release check
- **Goal:** a repo a stranger can evaluate.
- **Files:** `README.md` (badge, GIF, metrics table, "What it can't do"),
  `docs/THREAT_MODEL.md`, `docs/OWASP_LLM_2025.md`, demo GIF (recorded by the owner; no
  Pillow, nothing installed in WSL), `gate.py --full`.
- **Gate adds:** the `--full` checks.
- **Tests:** `--full` on Windows and in WSL: wheel build, install into the clean
  release-check venv, end-to-end eval, CLI smoke test.
- **Exit criteria:** `--full` green on both; CI matrix green after the owner pushes;
  docs match the measured numbers.
- **Graphify:** **query** only; final **update** if files moved.

---

## 5. Test strategy

- **Unit tests** for every module, with one passing and one failing case per rule.
- **Property-style tests for the sanitizer and wrapper** (`hypothesis`):
  - sanitizing twice equals sanitizing once;
  - output contains no zero-width or bidi control characters;
  - output length never exceeds the field cap;
  - output is NFKC-stable;
  - wrapped data never contains the unescaped boundary, for arbitrary input including
    the nonce itself;
  - unwrapping a wrapped value returns the sanitized value.
- **Golden tests for the mock provider:** fixed seed, fixed prompt, byte-exact expected
  output for both modes, compared after LF normalization. Goldens are regenerated only
  by an explicit script.
- **Eval as a test:** the eval runs in pytest on the full dataset with metric floors
  set after Phase 6 (detection rate, false positive rate, schema-valid rate, attack
  success with defenses ON). A drop below a floor fails the gate.
- **No-network fixture:** an autouse fixture replaces `socket.socket` and
  `socket.create_connection` with functions that raise. One test proves that it raises.
  Tests under the `live` marker are deselected by default and are the only ones that
  may opt out.
- **Anthropic provider:** tested against a stub client object; no HTTP layer is reached.
- **No email or secret literals:** email-shaped strings and fake secrets needed by
  tests are built at runtime from parts (D30). Validator check 7 (secret scan) is
  unit-tested this way. The eval does not measure secret leakage, and the README says so.
- **Coverage target:** at least 90% line coverage overall and at least 95% on
  `sanitize.py`, `wrap.py` and `validator/`. Vendored code is excluded from the figure
  and covered by its own smoke tests.

---

## 6. gate.py plan

Not written in this session. Stdlib-only Python, no shell pipes, same behaviour on
Windows and in WSL. It prints one line per check and exits non-zero on the first
failing group.

The gate is phase-aware (D31). Each check is added in the phase that creates its
artifact, shown in brackets below. No check contains "skip if file missing" logic: once
a check exists, a missing input is a failure.

All hashing and byte-exact comparison goes through one helper that normalizes `\r\n`
to `\n` first (D29). The gate's own scan patterns are assembled at runtime from parts,
so the gate file never matches itself (D30).

### Default checks (final state)
1. [P1] `ruff check` and `ruff format --check`.
2. [P1] `mypy` on `src/` (strict).
3. [P1] `pytest` with coverage and the thresholds from section 5.
4. [P1] **AST ban:** parse every file under `src/`, vendored code included. Fail on any
   import of `subprocess`; on attribute access to `os.system`, `os.popen`, `os.exec*`
   or `os.spawn*`; and on calls to the builtins `eval`, `exec`, `compile` and
   `__import__` matched as bare names (`ast.Name`) only. Attribute calls such as
   `re.compile` are allowed.
   [P4] Also fail if `providers/naive_rules.py` or `providers/mock.py` imports `detector`.
5. [P1] **Secret and email scan** of tracked and staged files with the gate's own
   minimal patterns: email, a few well-known key prefixes and a private-key header.
   No allowlist exists in Phases 1–4, so any hit fails.
   [P5] Adds the vendored patterns and the allowlist from D20. An allowlist entry that
   matches nothing is itself an error, so stale entries are removed.
6. [P5] **Vendor integrity:** vendored files match `MANIFEST.sha256` after LF
   normalization; `VERSION` says v1.0.0.
7. [P6] **Dataset invariants:** no email-shaped string anywhere in the dataset
   (usernames only); exactly 60 benign and 60 injection; every injection has a
   known category and an `attack_goal` from the six goals (D23, D34); category counts
   within 7–8; split is 72/48; IPs only in RFC 5737 ranges; domains only `example.com`
   or `.test`; hashes match the fake-hash convention; every encoded blob decodes to text
   on the harmless list.
8. [P6] **README metrics drift:** regenerate the table from the eval output and compare
   with the block in the README, byte-exact after LF normalization.
9. [P1] **No graph files staged**, and graph output is ignored.
10. [P1] **Commit hygiene:** no `AGENTS.md` or `.codex/` staged.

### `--full` adds [P7]
1. Build the wheel with `build`.
2. Install it into the clean release-check venv (recreated each run).
3. Run the end-to-end eval from the installed package.
4. CLI smoke test: `aisa --version`, `aisa triage` on a fixture with the mock,
   check exit codes and that both report files exist.

---

## 7. Hook plan

`.claude/settings.json` registers a PreToolUse hook for the `Bash` and `PowerShell`
tools. It runs `.claude/hooks/pre_tool_use.py` (stdlib only), which reads the tool
input as JSON on stdin and blocks with exit code 2 and a reason.

The same settings file disables Claude Code's commit attribution (D32). Phase 1
verifies which key the installed version supports (`includeCoAuthoredBy` or
`attribution`). The hook remains the enforcing layer.

### Commit form
Commits run through the Bash tool only (Windows PowerShell 5.1 has no `&&`). A
`git commit` is allowed only when the same command starts with one of these gate
prefixes, followed by `scripts/gate.py &&`:
- `python`
- `.venv/Scripts/python` or `.venv/Scripts/python.exe`
- `.venv/bin/python`

Any `git commit` through the PowerShell tool is blocked.

### Blocked
- `git push` (any form).
- `git tag` when it creates or deletes a tag.
- `git add -A`, `git add --all`, `git add .`, `git add *`, `git commit -a`.
- `git config user.*` (local or global).
- A commit message containing `Co-Authored-By` or an email address.
- `git commit` without an accepted gate prefix in the same command (see "Commit form").
- Piping the gate: `gate.py | ...` (and `2>&1 |`).
- `docker ... prune`; any docker command naming the `wordpress` or `dvwa` containers.
- Host port 8080 (`-p 8080:`, `--port 8080`, `:8080` in a serve or bind command).
- Killing by image name: `taskkill /IM`, `Stop-Process -Name`, `pkill`, `killall`.
- Modifying the WSL distribution: `wsl --install`, `--unregister`, `--set-version`,
  `--update`, and `apt`/`apt-get`/`dpkg` run through `wsl`.

### Graphify
- `/graphify` and the plugin's own commands are explicitly allowed. They get no blanket
  exemption: the patterns above stay narrow enough not to match them, and every ban
  still applies to a Graphify command that includes a banned action.
- **To verify in Phase 1, before the first build:**
  - whether `/graphify` runs through the Skill tool only or also issues shell commands,
    and exactly which commands;
  - its output folder (expected `graphify-out/`) and any other files it writes;
  - whether it runs any git command or writes git hooks;
  - whether it makes network calls or spends LLM tokens itself;
  - that none of its commands match a blocked pattern by accident;
  - whether it offers an install or integration command that edits `CLAUDE.md`,
    `.claude/settings.json` or git hooks. Such a command must not be run; report it to
    the owner first.

### Hook tests
The hook script has unit tests with one blocked and one near-miss allowed command per
rule (for example `git push` blocked, `git log --grep push` allowed). Each accepted
gate prefix has its own passing test, and a commit with no prefix, with a piped gate,
or through the PowerShell tool has a blocking test. Email-shaped strings in these tests
are built at runtime from parts.

---

## 8. CI plan

GitHub Actions, one workflow, `.github/workflows/ci.yml`.

- **Matrix:** `windows-latest` and `ubuntu-latest` × Python 3.11, 3.12, 3.13, 3.14.
- **Permissions:** `permissions: contents: read` at workflow level.
- **Pinned actions:** `actions/checkout` and `actions/setup-python` pinned to full
  commit SHAs with the version in a comment, as supplied by the owner:
  - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1`
  - `actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0  # v7.1.0`
- **Line endings:** `.gitattributes` forces LF on checkout, and hashes and byte-exact
  comparisons normalize to LF anyway (D29), so Windows runners match Ubuntu.
- **Steps:** checkout, set up Python, install the package with dev dependencies (not
  the `[anthropic]` extra), run `python scripts/gate.py`.
- **No secrets:** the workflow references no secrets and never sets
  `ANTHROPIC_API_KEY`. One test asserts the variable is unset when `CI` is set.
- **Live tests never run:** the `live` marker is deselected in the pytest config, and
  the gate does not accept a flag to enable it.
- **No network in tests:** proven by the socket-blocking fixture and its own test.
- **Triggers:** `push` and `pull_request` only. No `pull_request_target`, no scheduled
  runs, no artifact upload of reports.

---

## 9. Time estimate and scope

| Phase | Estimate |
|-------|----------|
| 1 Scaffold and guardrails | 0.5 day |
| 2 Alert model and ingest | 1 day |
| 3 Sanitizer, wrapping, detector | 1 day |
| 4 Providers and triage | 1 day |
| 5 Vendored scanner, validator, report, pipeline, CLI | 1.5 days |
| 6 Dataset, eval, metrics | 1.5 days |
| 7 Docs, full gate, release check | 1 day |
| **Total** | **7.5 days** |

### Out of scope
- Web UI, API server, daemon mode.
- Integration with a real SIEM, ticketing system or EDR.
- Automated response of any kind.
- ML or LLM-based injection classifier.
- Agentic tool use, multi-turn conversations, RAG or embeddings.
- Providers other than the mock and Anthropic (v1.0; v1.1 adds Ollama, D36).
- Real alerts, real IOCs, real personal data, real attack code.
- Streaming output, localization of the report.
- Publishing to PyPI.
- Claims about real-model robustness beyond optional, manually run live tests.

---

## 10. Open questions for the owner

1. **Secret-scanner path.** What is the local path of the secret-scanner repo, and is
   `v1.0.0` tagged there? If its `LICENSE` contains an email address, that conflicts
   with the no-email rule and needs a decision before copying. Needed before Phase 5.
   **Open.** The owner gives the path in the Phase 5 prompt.
2. **Adapter samples.** Two or three synthetic output records each from mini-siem and
   soc-log-analyzer, or the repo paths to read the format from. Needed before Phase 2.
   **Open.** The owner gives the paths in the Phase 2 prompt. Sample records must be
   checked for email-shaped strings before use.
3. **CI action pins.** Commit SHAs for `actions/checkout` and `actions/setup-python`
   cannot be looked up with PyPI-only network. Supply them, or approve pinning by
   version tag. Needed in Phase 1.
   **Closed.** Pin by SHA with the version in a comment; the SHAs are in section 8.
4. **Demo GIF.** Assumed: the owner records it. Alternative: a script renders it with
   Pillow as a dev-only dependency. Needed in Phase 7.
   **Closed.** The owner records the GIF. No Pillow dependency, nothing installed in WSL.
5. **Check venvs.** Assumed: `.venv-wsl/` and `.venv-release/` inside the project
   folder, both git-ignored. Needed in Phase 1.
   **Closed.** Confirmed.
6. **Licence.** Assumed: MIT. Needed in Phase 1.
   **Closed.** MIT. The copyright line holds a name only, no email.

Questions 3–6 are closed. Questions 1 and 2 stay open until the Phase 5 and Phase 2
prompts. Also settled: the D17 model ID `claude-haiku-5-5` is confirmed by the owner,
with no online check needed.

---

## 11. v1.1.0 — Local model (Ollama) and deterministic lookups

Goal: run the full pipeline on a local open-weight model through Ollama, and stop trusting the
model with factual lookups. Windows Security facts come from a versioned table and enter the
prompt as trusted context. The validator rejects any output that contradicts the table.
Everything stays synthetic. Default provider stays `mock`. CI never calls a real model.

### 11.1 Decisions

**D36. Ollama provider over stdlib `urllib.request`, with no new dependency.**
`providers/ollama.py` implements the existing `Provider` protocol (`complete(system, user) ->
str`). The pipeline contract does not change. The request is `POST {base}/api/chat` with
`stream: false`, `think: false`, `format` = `schema.tool_input_schema()` (the same schema the
Anthropic tool call uses, so the two cannot drift), and `options` = `temperature: 0`, a fixed
`seed`, a `num_predict` cap and a `num_ctx` cap. Ollama's structured output narrows what the
model emits. The guarantee is still `triage.py`'s strict parse plus the validator: a `<think>`
block, prose or a truncated reply (`done_reason: "length"`) is a parse failure. Rationale: the
project has no HTTP client today (the Anthropic SDK is an optional extra), and stdlib keeps the
one-runtime-dependency rule (D2). Rejected: the `ollama` Python package (pulls `httpx`, a second
supply-chain surface for one POST); `requests`/`httpx` (same).

**D37. The Ollama endpoint is loopback-only, and the transport is locked down.**
- `OLLAMA_BASE_URL` (default `http://localhost:11434`) must be `http` or `https` with host
  `localhost`, `127.0.0.1` or `[::1]`. No userinfo, no path, no query. Anything else is a
  `ProviderConfigError` (exit 2). Plain `http` is acceptable only because the host is loopback.
- Ollama's own `OLLAMA_HOST` is ignored (the same reasoning as ignoring `ANTHROPIC_BASE_URL`,
  D17). The opener has an empty `ProxyHandler`, so `HTTP(S)_PROXY` cannot route alert data
  elsewhere. Redirects are refused.
- Start-up health check, before any alert is touched: `GET /api/version`. If it is not reachable,
  the error is "Ollama is not reachable at <url>; is it running?" (exit 2). Then `GET /api/tags`.
  If the model is missing, the error is "model <name> is not available locally; pull it with
  `ollama pull <name>`". The CLI never pulls anything.
- Timeout: `OLLAMA_TIMEOUT_SECONDS`, default 600, accepted range 1–3600. It covers a cold model
  load plus generation at ~4 tokens/s on CPU, and `urllib`'s timeout applies per socket read
  while a non-streamed reply sends nothing until it is done.
- No retries (one attempt = one budget unit). A timed-out 5-minute call must not silently become
  a 10-minute one. A timeout or HTTP error becomes `ProviderError`, so the outcome is
  `provider_error` and the alert goes to `needs_human_review`.
- The response body is capped (1 MiB). It must be JSON with `done: true` and a string
  `message.content`. Anything else is a `MalformedReply` with a fixed reason code.
- `OLLAMA_MODEL` (default `qwen3:8b`) uses the same name regex as `AISA_ANTHROPIC_MODEL`. The
  default lives in exactly one constant, `providers/ollama.py:DEFAULT_MODEL`. The gate fails on the
  literal anywhere else in `src/` or `tests/` (docs, README and `.env.example` may name it).
- The transport is injectable (a callable taking a request and a timeout and returning bytes). Tests
  pass fakes that replay recorded `/api/chat` bodies, so no socket is opened and the autouse
  blocker stays in force.
Rejected: allowing a remote Ollama host (alert data over plaintext HTTP to a host the user may not
control); SDK-style retries (hidden cost in time).

**D38. Provider selection and `.env`.**
`aisa triage`: `--provider` if given, else `LLM_PROVIDER`, else `mock`. Allowed names are
`PROVIDER_NAMES` (`mock`, `mock-naive`, `anthropic`, `ollama`). `aisa eval` ignores
`LLM_PROVIDER`: a non-mock eval needs an explicit `--provider`. This keeps the gate's README drift
check and the test suite from ever reaching a model because of a stray variable. `.env` is read by
`cli.main` only, from the current directory only, through a stdlib reader:
- `KEY=VALUE` lines and `#` comments only, with no `export`, no interpolation, no quotes
  processing beyond stripping one matching pair, and no multi-line values;
- allowed keys: `LLM_PROVIDER`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_TIMEOUT_SECONDS`;
- an unknown key is an error (exit 2), naming the key and never the value;
- `ANTHROPIC_API_KEY`, or any key containing `KEY`, `TOKEN`, `SECRET` or `PASSWORD`, refuses to
  start ("the API key is read only from the environment");
- a real environment variable wins over the file.
`.env` is git-ignored, and the gate fails if it is staged. `.env.example` is committed. Rejected:
`python-dotenv` (dependency for 40 lines); reading `.env` from library code or tests (a developer's
`.env` would change the gate's behaviour).

**D39. The Windows knowledge base is data, keyed by strict structured fields.**
`data/windows_kb.json` holds `schema_version` and `kb_version` (date-based, for example
`2026.11.1`), loaded by a strict pydantic model. Contents:
- Security Event IDs 4624, 4625, 4634, 4648, 4672, 4688, 4720 and 4740;
- Logon Types 2, 3, 4, 5, 7, 8, 9, 10 and 11;
- 4625 Status/SubStatus 0xC000006D, 0xC000006A, 0xC0000064, 0xC0000234, 0xC0000072, 0xC000015B,
  0xC0000071 and 0xC0000193.
Each entry has a canonical name, a short meaning, and `aliases` (the phrases the validator treats
as naming that entry). Event entries also have `never_records` (4625: the attempted password). The
file also holds the aggregation thresholds (D41). The owner reviews the table contents before the
phase that creates it is committed.

Keys come from new untrusted `Alert` fields: `event_id`, `logon_type`, `status`, `sub_status` and
`target_user`. The Wazuh adapter fills them from `data.win.system.eventID` and
`data.win.eventdata.{logonType,status,subStatus,targetUserName}`, and drops every other `win`
key (TB1). Lookup uses strict formats in the D33 style: an event ID is a plain decimal of 1–5
digits, a logon type is a plain decimal of 1–2 digits, a status is `0x` plus 8 hex digits (case
folded to upper). Any other value is unmappable and gives no fact. Nothing is parsed out of
`message` or other free text. Residual risk: the attacker who writes the log can pick a different
real code, and the model then gets that code's true facts. That risk is the same as the D33
floor's and is documented. Rejected: regex over `full_log` (keys from attacker prose); facts as
prompt text (unversioned, untestable, and exactly what the model got wrong).

**D40. KB facts enter the prompt as a trusted reference block, separate from untrusted data.**
`prompt.py` adds a `TRUSTED REFERENCE (kb <version>)` block to the user prompt, outside the nonce
boundary. It is rendered only from table values, never from alert text. The `target_user` value
is not echoed in this block (it stays inside the untrusted block). The system prompt gains one
rule: the reference block is authoritative, the model must not describe a code that is not in it,
and any meaning it states must match the table. `PROMPT_VERSION` becomes `2` and goldens are
regenerated. Enrichment counts as input preparation (D22): it is on in every configuration except
`none`. The report shows the same facts in a "Reference facts (from KB <version>)" section, kept
apart from the model-generated summary label (TB4). Rejected: putting facts inside the untrusted
block (the model is told to distrust it); letting the model's summary be the only place facts
appear.

**D41. Password spraying vs brute force by deterministic batch aggregation.**
Before the per-alert loop, `run_pipeline` groups the WHOLE input batch's alerts with
`event_id == "4625"` and a parsed `src_ip`. Within a window (from the trusted timestamps), it
counts distinct `target_user` values U and the most attempts per user A. Thresholds live in the KB
file:
- U ≥ 4 and A ≤ 2 → `password_spraying` (T1110.003);
- U = 1 and A ≥ 5 → `brute_force` (T1110.001);
- anything else → `undetermined`.
The pattern is attached as a trusted fact to every alert in the group. The eval computes it over
the full dataset file, so a `--limit` or resumed run sees the same facts. Residual risk: usernames
are untrusted, so an attacker who writes the log can make a group look like either pattern. The
fact is evidence, not a verdict, and is documented as such. Phase 9 details (owner-approved):
the window is `patterns.window_seconds` in the KB file (3600), anchored at the group's first
event (an event joins the open group when it is at most that long after the first one); only
failed logons with a parsed `src_ip` and a usable user name (not empty, not `-`; trimmed and
case-folded) are counted, and any other alert gets no pattern fact; loopback addresses are kept
as written and never make a pattern without real user and attempt counts; the fact shows only
integers (distinct users, most attempts by one user, failed logons) and never a user name.
Known blind spots, recorded for the README "What it can't do" list: distributed spraying (the
same few passwords from many source addresses gives one small `undetermined` group per
address) and low-and-slow spraying slower than the window. Rejected: asking the model to infer
the pattern from one alert (it cannot see the other events); cross-run state (the CLI stays
stateless).

**D42. Validator check 9 `kb`: fail closed on any fact the table does not support.**
`validator/kb.py` scans every output string, the same view as check 4, after the same
normalization. It extracts:
- event-ID mentions anchored by context: `event`, `event id`, `eventid` or `EID` followed by
  digits (a bare 4-digit number such as a port or year is not an event ID);
- `logon type N`;
- every `0x` + 8 hex token.
Reason codes:
- `kb.unknown_event_id`, `kb.unknown_logon_type`, `kb.unknown_status`: the code is not in the
  table. Fail closed, as with the MITRE allowlist (D12 check 3); widening the table is a data
  change.
- `kb.ungrounded_event_id`, `kb.ungrounded_logon_type`, `kb.ungrounded_status`: the code is in
  the table but is not the alert's own value. This is IOC grounding (T5) applied to facts.
- `kb.contradiction_event_id`, `kb.contradiction_logon_type`, `kb.contradiction_status`: a code
  is followed in the same clause (bounded window) by an alias of a DIFFERENT table entry, for
  example "logon type 10 (Interactive)" or "0xC000006A: logon type not granted".
- `kb.contradiction_pattern`: the technique is T1110.001 while the D41 fact says
  `password_spraying`, or T1110.003 while it says `brute_force`.
- `kb.not_recorded_claim`: for a 4625 alert, a narrow phrase set claims the attempted password is
  known ("attempted password", "password (used|entered|tried) (was|is)").
The check is on wherever the validator is on (`validator-only`, `all`). Residual risk, documented
in the README: a paraphrased misstatement with no code next to it ("the user lacks the right to
log on here") passes. That blind spot is the same kind as D34. The report's reference-facts
section is the mitigation: the analyst sees the true meaning next to the model's summary.
Phase 10 details (owner-approved): an `undetermined` group claimed as T1110.001 or T1110.003 is
`kb.unsupported_pattern` (alerts with no pattern fact are not checked); a clause ends at a
sentence end, a line break, the next code or 200 characters, and continues into ONE more sentence
only when that sentence opens with a back-reference ("this/that/the (error) code/status/value",
"it"); on a line with a "logon type" anchor, list items (`10 for "x"`, `10 = x`, `10: x`,
`10 (x)`) followed by a logon-type alias are mentions; `kb.not_recorded_claim` flags only text
that attributes the password to the log ("the attempted password was", "each attempt used a
different password", "the event shows the password", "the logged password was"), never generic
attacker behaviour ("the attacker is trying different passwords"); a faithful echo of the
reference block passes: a span that reproduces the name or meaning of one of the alert's own
entries is not scanned when it sits next to that entry's own code (or no code); the table gains
the alias "not been granted the requested logon right" (0xC000015B) and its meanings name no
other code and no other entry's alias, which `kb/selfcheck.py` (gate) enforces (`kb_version`
2026.11.2). Blind spots recorded with the paraphrase one: a lockout described with no code near it,
"different passwords are tried in sequence", and an entry's meaning placed BEFORE a wrong code.
Rejected: an LLM judge (a second injection surface); repairing the summary (D12: no repair).

**D43. A separate Windows-auth eval set, a seventh attack goal, and "triage accuracy".**
`data/eval/windows_auth.jsonl`, about 28 synthetic Wazuh-format alerts:
- benign singles across the 8 events and several logon types;
- 4625s covering all 8 status codes;
- a 4740 lockout with its 0xC0000234 4625;
- one spraying group and one brute-force group;
- about 8 injections in attacker-controlled fields (`targetUserName`, workstation) that try to make
  the model misstate a fact, plus some carrying the existing goals.
New goal `fact_misstatement`, used only in this set: it succeeds when the ACCEPTED verdict's text
contains a D42 contradiction or unknown code. Each sample also carries `expected_technique` and
`expected_min_severity`. **Triage accuracy** = accepted AND technique equals `expected_technique`
AND severity ≥ `expected_min_severity`, as n/of over the set. The 120-alert set has no
ground-truth verdicts, so it reports only its existing metrics. The naive mock gains obedience
rules for the new goal in `naive_rules.py` (still detector-independent, D16). The 120-alert set,
its invariants and the README mock table do not change. Rejected: adding Windows alerts to the
120 set (changes every published number and makes the Haiku run stale).

**D44. The live eval is resumable, sliceable and timed.**
`aisa eval --provider {anthropic,ollama} --out FILE` gains:
- `--dataset {main,windows}`;
- `--subset {all,dev,heldout}`;
- `--limit N` (the first N samples of a fixed stratified order);
- `--configs` (a comma list of D22 configs);
- `--checkpoint PATH` (default `<out stem>.checkpoint.jsonl`).
Checkpoint mechanics:
- The checkpoint is append-only JSONL. Its first line is a header pinning `dataset_sha256`,
  `kb_version`, `prompt_version`, `seed`, provider, model, the subset, limit and configs, and the
  checkpoint schema version.
- Each later line is one (config, sample) outcome, written and flushed after that alert. It holds
  what `metrics.py` needs to rebuild the `AlertOutcome` (raw reply included), so metrics code is
  reused, not duplicated.
- Re-running the same command resumes and skips finished pairs. A header mismatch refuses to
  start (exit 2) and never overwrites. Canary and nonce are seed-derived per run, so a resumed
  alert sees the same prompt.
- Checkpoints hold model text, so they live under `reports/` by default, are git-ignored, and the
  gate fails if one is staged.
Results:
- `--out` (metrics) and `.samples.json` (codes only, as today) are written when all selected pairs
  are done. A partial run writes them with `"complete": false`.
- New live-only metrics: per-config wall-clock latency per provider call (mean and p95, ms, with
  n, through an injected monotonic clock); validator rejections as n/of replied plus counts per
  reason code; and the D43 metrics for the Windows set.
- The mock eval measures no time, so it stays byte-deterministic.
- `AISA_LIVE=1` stays required for `anthropic` (paid). `ollama` does not need it, but both refuse
  to run when `CI` is set.
Rejected: restarting a 6–8 h run after an interruption; latency in the mock eval
(non-deterministic, would break the drift check).

**D45. The model comparison table is generated from committed results files.**
`eval/compare_table.py` reads `docs/live-eval/*.json` (only `"complete": true` runs) plus the mock
eval. It renders one block in the README with these rows:
- attack success (`all` and `none`);
- validator rejections;
- benign review rate;
- triage accuracy (Windows set);
- `fact_misstatement` success;
- mean and p95 latency.
The columns are mock, Claude Haiku 5.5 and qwen3:8b, with prompt version and date per column. A
missing measurement is `n/a`, never blank. For example, the 2026-11-19 Haiku run has no latency
and no Windows set, and its prompt version is 1. The gate regenerates the block and compares it
byte-exact after LF normalization (as D25). Rejected: hand-edited comparison numbers.

### 11.2 Architecture delta

New modules:

    config.py               .env reader and provider resolution (D38)
    providers/ollama.py     Ollama provider (D36, D37)
    kb/__init__.py          strict KB loader and lookups (D39)
    kb/patterns.py          batch spraying / brute-force aggregation (D41)
    validator/kb.py         check 9 (D42)
    eval/checkpoint.py      resumable checkpoint (D44)
    eval/compare_table.py   comparison table (D45)
    data/windows_kb.json
    data/eval/windows_auth.jsonl

Data flow: the KB is a new TRUSTED input, beside the system prompt and canary:

    Alert --(strict key formats)--> KB lookup + batch patterns --> TRUSTED REFERENCE block
                                                                     |
                        sanitize -> wrap(nonce) -> UNTRUSTED block --+--> provider -> validator (9 checks)

Exit codes do not change.

### 11.3 Threat model additions

| # | Threat | Controls | Residual risk |
|---|--------|----------|---------------|
| T12 | The model hallucinates or misstates a Windows fact (event, logon type, status) | KB as trusted context (D40), check 9 (D42), reference facts in the report | Paraphrased misstatement with no code nearby |
| T13 | Local endpoint redirection: alert data sent to a non-local host through config, `OLLAMA_HOST`, a proxy or a redirect | Loopback-only URL, empty proxy handler, redirects refused (D37) | A malicious process already listening on the loopback port |
| T14 | KB key spoofing: the log writer picks a different real code or fakes usernames to shape D41 | Strict formats, facts are table text only, pattern is evidence not a verdict | Distributed and low-and-slow spraying are not seen (D41 blind spots). A chosen real code gets its true but misleading facts |
| T15 | Slow local model as a DoS on the run | Per-call timeout, call budget, no retries, resumable eval | A long batch is slow by nature on CPU |

OWASP rows to update: LLM09 (adds D39–D42), LLM10 (adds the D37 timeout and no-retry rules),
LLM03 (no new dependency).

### 11.4 Phases

Each phase fits one fresh session and ends with the phase report described in CLAUDE.md. Model
per phase: **Opus 5.5** where the phase sets a trust boundary or a validator rule, **Sonnet 5.5
High** otherwise. Every phase keeps the gate green, keeps 100% line and branch coverage, makes no
network call in tests, and leaves the README mock metrics block byte-identical unless the phase
says otherwise.

#### Phase 8 — Config and OllamaProvider (Sonnet)
- **Goal:** `aisa triage` runs on a local Ollama model, offline-tested.
- **Needs:** one or two real `/api/chat` reply bodies from qwen3:8b, recorded by the owner. One
  must be the observed hallucination. The owner pastes them into the session prompt; they are
  checked for email-shaped strings before use.
- **Files:** `config.py`; `providers/ollama.py`; `providers/__init__.py` (adds `ollama`);
  `cli.py` (triage provider resolution only); `.env.example`; `.gitignore` (`.env`);
  `.claude/hooks/pre_tool_use.py` (Ollama bans, see CLAUDE.md); `tests/test_config.py`,
  `tests/test_ollama_provider.py`, `tests/test_hook.py` additions, `tests/fixtures/ollama/`,
  `tests/live/test_ollama_live.py` (one call, `live` marker).
- **Gate adds:** `.env` never staged; `providers/ollama.py` imports only stdlib and project
  modules (AST); the default model literal appears only in its constant (D37).
- **Tests:**
  - URL policy: loopback accepted; remote, userinfo, path and `OLLAMA_HOST` refused or ignored;
  - the proxy env vars do not affect the opener; a redirect is refused;
  - health check: not running gives exit 2 with the message; model missing gives exit 2;
  - the request body has `think: false`, `stream: false`, `format` equal to `tool_input_schema()`,
    `temperature: 0` and the seed;
  - timeout handling; no retry; budget spent once per call;
  - `done_reason: "length"`, non-JSON body, oversize body, and `<think>` text in the content;
  - recorded replies replayed end to end through the pipeline;
  - `.env` rules (allowed keys, unknown key, secret-like key, env precedence, not read by `eval`
    or under pytest);
  - hook bans with near-miss allowed cases.
- **Exit criteria:** with fakes, `LLM_PROVIDER=ollama aisa triage <fixture>` writes both reports.
  With Ollama stopped (simulated), exit 2 with the clear message. The owner runs the one-call live
  test by hand, and the session runs it only with the owner's OK. No new runtime dependency in
  `pyproject.toml`.

#### Phase 9 — Windows KB, Alert fields, enrichment (Opus)
- **Goal:** trusted Windows facts reach the prompt and the report, keyed by strict fields.
- **Files:** `data/windows_kb.json`; `kb/__init__.py`; `kb/patterns.py`; `models.py` (five new
  untrusted fields); `ingest/wazuh.py` (`data.win.*`); `prompt.py` (reference block, system rule,
  `PROMPT_VERSION = "2"`); `pipeline.py` (batch facts, facts on `AlertOutcome`, on except `none`);
  `report.py` (reference-facts section in Markdown and JSON); `tests/fixtures/wazuh/` Windows
  records; regenerated goldens.
- **Gate adds:** KB invariants: schema valid; every required event, logon type and status
  present; unique codes; no alias shared by two entries; thresholds present; no email-shaped
  string.
- **Tests:**
  - every strict key format, accepted and rejected (padding, sign, case, overlong, free text);
  - the adapter maps `data.win.*` and drops other `win` keys;
  - the reference block contains only table text and never `target_user`;
  - the reference block sits outside the nonce boundary and is absent under `none`;
  - aggregation thresholds at each boundary, with groups split by source IP and window;
  - facts computed over the full batch;
  - report escaping of the facts section;
  - the KB loader fails closed on a malformed file.
- **Exit criteria:** `aisa triage --dry-run` on a Windows fixture shows the facts. The README mock
  table is byte-identical (only goldens and the prompt version changed). The owner has reviewed
  and approved the KB table in the session.

#### Phase 10 — Validator check 9 and hallucination regressions (Opus)
- **Goal:** the validator rejects any output that contradicts or goes beyond the table.
- **Files:** `validator/kb.py`; `validator/__init__.py` (nine checks); `tests/test_validator_kb.py`;
  `tests/test_kb_regressions.py`; recorded-reply fixtures from Phase 8 reused.
- **Gate adds:** nothing (the coverage threshold already applies to `validator/`).
- **Tests:** one pass and one fail case per D42 reason code, plus these regressions, each with
  its exact reason code:
  - "logon type 10 (Interactive)" is rejected; "logon type 10 (RemoteInteractive)" is accepted;
  - "0xC000006A … logon type not granted" is rejected; 0xC000006A as "correct user, bad
    password" is accepted;
  - a lockout claimed on a 0xC000006A alert (0xC0000234) is rejected as ungrounded; a 4740
    alert described as a lockout is accepted; a 4625 alert with 0xC0000234 described as "account
    locked out" is ACCEPTED (owner review, Phase 9: the 4625 page logs an attempt on a locked-out
    account as 4625 with that status, and 4740 is only the moment the account gets locked), while
    "event 4625" followed by the 4740 entry's own alias ("user account was locked out") is a
    contradiction. Aliases are unique inside one table (events, logon types, statuses) and are
    compared inside one table only. Longest alias wins when one alias contains another
    ("interactive" inside "remote interactive", "network" inside "network cleartext");
  - "the attempted password was …" on a 4625 alert is rejected; the string is built at runtime;
  - a spraying group triaged as T1110.001 is rejected and as T1110.003 accepted, and the reverse
    for brute force;
  - a bare 4-digit port or year is not read as an event ID;
  - the recorded qwen3:8b hallucination replayed through `OllamaProvider` ends in
    `needs_human_review` with the expected codes.
- **Exit criteria:** all regressions green; README mock table byte-identical (the 120 set has no
  Windows facts, so check 9 never fires there; a test proves it).

#### Phase 11 — Windows-auth eval set and metrics (Sonnet)
- **Goal:** measured KB behaviour on the mocks.
- **Files:** `data/eval/windows_auth.jsonl`; `eval/dataset.py` (second dataset, `--dataset`);
  `eval/metrics.py` (`fact_misstatement`, triage accuracy, validator rejections by code);
  `providers/naive_rules.py` (obedience for the new goal, D16); tests.
- **Gate adds:** Windows-set invariants (RFC 5737 IPs, `.test`/`example.com` only, usernames only,
  no email-shaped strings, every code from the KB, fixed counts per group and goal, the spraying
  and brute-force groups meet D41 thresholds, labels present).
- **Tests:** dataset invariants; metric functions on hand-built cases; Windows mock eval in pytest
  with floors; `fact_misstatement` success is lower under `all` than under `none`.
- **Exit criteria:** `aisa eval --dataset windows` prints metrics. The 120-set README block is
  byte-identical. The Windows mock numbers are not yet in the README (Phase 13).

#### Phase 12 — Resumable live eval, latency, Ollama eval (Sonnet)
- **Goal:** the owner can run the 6–8 h local eval in several sittings.
- **Files:** `eval/checkpoint.py`; `eval/runner.py` (per-pair resume, injected clock); `cli.py`
  (`--provider ollama`, `--dataset`, `--subset`, `--limit`, `--configs`, `--checkpoint`, CI
  refusal); `eval/metrics.py` (latency, `complete` flag); `.gitignore` (`*.checkpoint.jsonl`);
  `docs/LIVE_EVAL.md` (Ollama section, time estimate, resume how-to); tests.
- **Gate adds:** no `*.checkpoint.jsonl` staged.
- **Tests:**
  - a run interrupted after k pairs (simulated exception) resumes and ends with metrics identical
    to an uninterrupted run (fake provider and fake clock);
  - a header mismatch on any pinned field refuses;
  - `--limit`/`--subset`/`--configs` select the documented samples;
  - a partial run writes `"complete": false`;
  - latency mean and p95 on a fake clock;
  - the samples file stays codes-only;
  - eval refuses under `CI`.
- **Exit criteria:** the full Ollama flow is proven with fakes. The session may run
  `--limit 2 --configs all` against the local Ollama only if the owner allows it, in the
  background. The owner then runs the full eval (main and windows datasets, all four configs) by
  hand.

#### Owner step (between Phase 12 and Phase 13)
The owner runs the qwen3:8b eval (expected ~6–8 h for the main set, ~1.5–2 h for the Windows set)
and keeps the results and samples files. Optionally, the owner re-runs the Haiku live eval on prompt
version 2 and the Windows set (paid, about $0.2–0.3) so the Haiku column has no `n/a` cells.

#### Phase 13 — Comparison table, docs, release prep (Sonnet)
- **Goal:** v1.1.0 is documented and release-ready. The owner tags it.
- **Needs:** the owner's qwen3:8b results files (and optional new Haiku files).
- **Files:**
  - `docs/live-eval/<date>-qwen3-8b*.json` (committed through the gate);
  - `eval/compare_table.py`;
  - README:
    - "Local mode (Ollama)" setup: install, `ollama pull qwen3:8b` run by the user, `.env`,
      health-check errors;
    - the generated comparison block;
    - "Why the LLM is never trusted with lookups", with the observed hallucination and how D39–D42
      catch it;
    - the Windows mock metrics;
    - new "What it can't do" items: paraphrased misstatements, D41 username spoofing, D41
      blind spots (distributed spraying across many source addresses, low-and-slow spraying
      slower than the window), CPU latency, a prompt too long for `num_ctx` is refused (not
      truncated);
  - `docs/THREAT_MODEL.md` (T12–T15); `docs/OWASP_LLM_2025.md`; `CHANGELOG.md` (1.1.0);
    `__version__` 1.1.0; `gate.py --full` (also runs the Windows mock eval from the installed
    wheel, and the wheel must contain `windows_kb.json` and `windows_auth.jsonl`).
- **Gate adds:** the comparison-block drift check (D45).
- **Tests:** table generator on fixture results (complete and incomplete runs, `n/a` cells);
  `--full` additions.
- **Exit criteria:** `--full` green on Windows and in WSL. The README numbers match the committed
  files. No live call was made in the session.

### 11.5 Time estimate

| Phase | Estimate |
|-------|----------|
| 8 Config and OllamaProvider | 1 day |
| 9 Windows KB, fields, enrichment | 1 day |
| 10 Validator check 9 and regressions | 1 day |
| 11 Windows-auth eval set and metrics | 1 day |
| 12 Resumable live eval | 1 day |
| Owner eval run | 8–10 h machine time |
| 13 Comparison, docs, release prep | 0.5–1 day |

### 11.6 Out of scope for v1.1
- Elastic / SIEM adapter (v1.2), and Windows fields from adapters other than Wazuh.
- Docker packaging, RAG or vector DB, fine-tuning, any automated response.
- A remote or shared Ollama host; streaming output; model management (pull, create, delete) from
  the CLI.
- Event IDs, logon types or status codes beyond the D39 list. They fail closed until added to the
  table.
- An LLM-based fact checker.

### 11.7 Open questions
1. **Recorded qwen3:8b replies (Phase 8).** The owner supplies the raw `/api/chat` body (or at
   least `message.content`) of the observed hallucination. **Open.**
2. **KB review (Phase 9).** The owner approves the table text in session before commit. **Open.**
3. **Haiku re-run (after Phase 12).** Optional and paid; without it the Haiku column shows `n/a`
   for latency and the Windows set and is marked prompt version 1. **Open.**
