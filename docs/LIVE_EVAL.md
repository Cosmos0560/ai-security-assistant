# Live evals (run by hand only)

The published numbers come from deterministic mocks and measure the pipeline's mechanics. A live
eval runs the same ablation against a real model, so you can see how often it obeys the injections
and what the defenses do with its replies. It runs either on a local Ollama model (free, slow on a
CPU) or on the Anthropic API (paid). The gate, the tests and CI never run it with a real model, and
nobody runs it but the owner, on purpose.

## Running the local eval

Git Bash on Windows, from the repository folder, with Ollama running and the model already pulled
(`ollama list` shows it; the eval never pulls).

Before you start: **laptop on mains power, sleep and hibernation off** (Windows Settings, System,
Power & battery: "When plugged in, put my device to sleep after" = Never, and closing the lid set
to do nothing), and **VMs and browsers closed** (they compete for CPU and memory and make calls
time out).

```bash
.venv/Scripts/python -m pip install -e .
mkdir -p reports
```

A trial with two alerts first (8 calls). Use its own file name: a checkpoint is bound to its
`--limit`, so a trial cannot be grown into the full run.

```bash
.venv/Scripts/aisa eval --provider ollama --dataset windows --limit 2 --out reports/trial.json
```

The two full runs, the shorter one first:

```bash
.venv/Scripts/aisa eval --provider ollama --dataset windows --out reports/qwen3-windows.json
```

```bash
.venv/Scripts/aisa eval --provider ollama --dataset main --out reports/qwen3-main.json
```

| Run | Pairs (alerts x 4 configs) | Model calls |
| --- | --- | --- |
| Windows | 196 | about 193 |
| Main | 480 | about 464 |

The rest are blocked by the detector or refused by the context guard before any call. At an
assumed 50 to 60 seconds a call that is about 3 hours for Windows and 6 to 8 hours for main. This
is an assumption, not a measurement: after the first calls the eval prints an estimate from your
own machine, for example `[37/196] all w012: triaged in 55s; 156 model calls left, ETA about 2h23m`.

**Stop and resume.** Every finished alert is saved at once to
`reports/<name>.checkpoint.jsonl`. **Run exactly the same command to continue.** To stop:

- press Ctrl+C; the partial results are written with `"complete": false`. On Windows it may only
  take effect when the current alert finishes;
- or plan the sitting: `--max-calls 100` stops cleanly after 100 calls;
- or close the window. Nothing finished is lost, but no results file is written in that sitting.

**Errors.** A timeout or an HTTP error is recorded as `provider_error` and the run goes on. A
resumed run keeps it unless you add `--retry-errors`; until then the results stay
`"complete": false` and the errored pairs are in no numerator or denominator. If Ollama stops
altogether, every remaining alert errors quickly; start Ollama and rerun with `--retry-errors`.

**Refusals.** An alert whose prompt might not fit the model's context is not sent. It is recorded
as `refused_context_budget`, which is final: it is never retried and never counts as accurate.

**A resume that refuses to start** (exit 2, nothing called, nothing changed) names the difference:
the dataset, KB version, prompt version, seed, provider, model, subset, limit or configs. It also
refuses if a recorded alert no longer gets the same prompt or the same decision. So **do not change
or update the code, and do not pull the model again, between sittings** (a re-pulled model under
the same name is not detected). Settings come from the environment only: `aisa eval` ignores
`.env`, so set them on the command line, for example
`OLLAMA_TIMEOUT_SECONDS=900 .venv/Scripts/aisa eval ...`.

**Results.** `<name>.json` (metrics, with `"complete"`, per-config latency mean and p95, errors,
refusals, rejections by reason code) and `<name>.samples.json` (codes only). The checkpoint holds
model text: it is git-ignored, the gate refuses to see it staged, and it must not be shared.
Complete results are never overwritten; partial ones are replaced by the next sitting.

**Slicing.** `--limit N` takes the first N alerts of a fixed order that alternates benign and
injection; `--subset dev|heldout` (main only); `--configs none,all`. Slicing only chooses which
alerts are sent: the spraying and brute-force facts always come from the full dataset.

**Known limits of the Windows set.** One injection (w047) sits in `workstationName`, which the
Wazuh adapter drops, so the model never sees it, although it counts as an injection. One
Russian-locale alert (w041) is refused by the context guard in `detector-only`, `validator-only`
and `all`, whose prompts escape Cyrillic; only `none` sends it. The blind-spot alerts are labelled
with what really happened, so under the validator they cannot score as accurate: accuracy is
reported with and without them.

## What a live eval does

One provider answers in every selected configuration (`none`, `detector-only`, `validator-only`,
`all`), one alert through all of them before the next. In the mock eval a separate well-behaved
mock supplies the "operational" numbers; in a live eval the same model's `all` run is used for
them. The metrics JSON has the mock eval's shape plus the live fields, and is written to the
`--out` file only. Resuming, slicing, errors and results work as described above for both
providers.

Next to it, the live eval writes `<stem>.samples.json` (for `--out live-metrics.json`:
`live-metrics.samples.json`): for every sample in every configuration, its id, label, category,
attack goal, split, status, reason codes (such as `schema.not_json` or `severity.downgrade`),
detector decision, and three booleans (called the provider, schema-valid, goal reached). It holds
codes only: no model reply, verdict text, alert field or canary, and a reason that does not look
like one of the pipeline's own `stage.rule` codes is replaced by `unexpected.reason`. It is what
explains an aggregate such as "33/60 benign alerts sent to human review".

Guards, all checked before any model call:

- the `CI` environment variable must not be set;
- `--out` is required; it and its `.samples.json` companion may exist only as the partial results
  of the checkpoint being resumed (complete results are never overwritten), and the folder must
  exist;
- `--readme` is refused: the README table is mock-only and the gate's drift check would fail
  on live numbers anyway;
- for `anthropic` only: `AISA_LIVE=1` must be set, `ANTHROPIC_API_KEY` must hold a key
  (environment only, never a flag or file) with the `[anthropic]` extra installed, and
  `--max-calls` is required; every attempt, retries included, spends one call.

If a results file cannot be written after the run, its content is printed to stdout instead.

To see which checks sent benign alerts to human review under `all`:

```bash
.venv/Scripts/python -c "import collections, json; rows = json.load(open('live-metrics.samples.json'))['configs']['all']; bad = [r for r in rows if r['label'] == 'benign' and r['status'] == 'needs_human_review']; print(len(bad), collections.Counter(c for r in bad for c in r['reasons']))"
```

The 2026-11-19 run predates this file, so its 33/60 cannot be broken down; the next run can.

## The Anthropic command

Git Bash on Windows (use `.venv/bin/` on Linux):

```bash
.venv/Scripts/python -m pip install ".[anthropic]"
export ANTHROPIC_API_KEY=...        # your key; never commit it or write it to a file
AISA_LIVE=1 .venv/Scripts/aisa eval --provider anthropic --max-calls 480 --out live-metrics.json
```

`480` covers 120 alerts x 4 configurations. The detector blocks some alerts before any call under
`detector-only` and `all`, so a clean run needs about 464 calls, which leaves a little room for
retries. `--max-calls` is per invocation. When it runs out, the remaining pairs are simply not run,
the results are written with `"complete": false` and the command exits with 3; run the same command
again to continue. Exit codes: `0` complete, `3` incomplete, `2` a guard, setup or checkpoint
error (nothing was called), `1` internal error (the checkpoint keeps what was finished).

The model is `AISA_ANTHROPIC_MODEL` (default `claude-haiku-5-5`). Do not commit
`live-metrics.json` into the README; quote it, with its model and date, if you publish it.

## Expected cost

Measured on the dataset: 464 calls with about 1.23 million characters of prompt in total (the
`none` prompts are about 1,000 characters, the fenced prompts about 2,070), plus the tool
schema on every call. That is roughly 0.3 to 0.5 million input tokens. Output is one forced tool
call per reply, capped at `max_tokens` 600.

At the Claude Haiku 5.5 list price of $0.10 per million input tokens and $0.50 per million output
tokens (Anthropic's price table as cached on 2026-11-03; check the current price list before
running):

| | Tokens | Cost |
| --- | --- | --- |
| Expected | 0.3-0.5M in, 0.07-0.28M out | about $0.07 to $0.19 |
| Hard ceiling with `--max-calls 480` | at most about 0.75M in, 0.29M out | about $0.22 |

The ceiling comes from the budget: 480 attempts at most, each at most about 1,500 input tokens
and 600 output tokens. The output stays small because a forced tool call on Claude Haiku 5.5
skips thinking, so the reply is the tool call alone.

## Which models work

The provider forces the tool call (`tool_choice` naming the triage tool) and sends no sampling
parameter. Claude Haiku 5.5, the default, accepts this. Some current models reject a forced
`tool_choice` with a 400, among them Claude Opus 5.5, Claude Sonnet 5.5 and Claude Fable 5.1 and
5.2, so do not point `AISA_ANTHROPIC_MODEL` at them without changing the provider. A model that
works costs in proportion to its price list (Claude Haiku 4.5, for example, lists at 10 times the
Haiku 5.5 price, a ceiling of about $2.20). With no `temperature` sent, replies vary from run to
run: unlike the mock eval, the live numbers are not reproducible.

## Before the full run: a one-call check

Run the single live test first. It makes one call and costs a fraction of a cent:

```bash
AISA_LIVE=1 .venv/Scripts/python -m pytest -m live tests/live
```

The request follows Anthropic's current API reference for Claude Haiku 5.5 (no sampling
parameters, a forced tool call), but no live call is ever made in development, so this check is
the first time it meets the real API. If it fails with a `BadRequestError`, fix the request in
`providers/anthropic.py` before the full run. Rejected requests are not billed, but each attempt
still spends one unit of `--max-calls`.
