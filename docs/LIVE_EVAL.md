# Optional live eval (run by hand only)

The published numbers come from deterministic mocks and measure the pipeline's mechanics. The
live eval runs the same 120-alert ablation against the real model, so you can see how often a real
model obeys the injections and what the defenses do with its replies. It spends real money, so it
is never run by the gate, the tests or CI, and nobody runs it but the owner, on purpose.

## What it does

`aisa eval --provider anthropic` sends the packaged dataset through all four configurations
(`none`, `detector-only`, `validator-only`, `all`) with ONE Anthropic provider and ONE shared call
budget. In the mock eval a separate well-behaved mock supplies the "operational" numbers; in the
live eval the same model's `all` run is used for them. The metrics JSON has the same shape as the
mock eval's and is written to the `--out` file only.

Next to it, the live eval writes `<stem>.samples.json` (for `--out live-metrics.json`:
`live-metrics.samples.json`): for every sample in every configuration, its id, label, category,
attack goal, split, status, reason codes (such as `schema.not_json` or `severity.downgrade`),
detector decision, and three booleans (called the provider, schema-valid, goal reached). It holds
codes only: no model reply, verdict text, alert field or canary, and a reason that does not look
like one of the pipeline's own `stage.rule` codes is replaced by `unexpected.reason`. It is what
explains an aggregate such as "33/60 benign alerts sent to human review".

Guards, all checked before any call is made:

- `AISA_LIVE=1` must be set, and `ANTHROPIC_API_KEY` must hold a key (environment only, never a
  flag or file) with the `[anthropic]` extra installed;
- `--max-calls` is required; every attempt, retries included, spends one call;
- `--out` is required; neither it nor its `.samples.json` companion may exist yet (results are
  never overwritten), and its folder must exist;
- `--readme` is refused: the README table is mock-only and the gate's drift check would fail
  on live numbers anyway.

If a results file cannot be written after the run, its content is printed to stdout instead, so
a paid run is not lost.

To see which checks sent benign alerts to human review under `all`:

```bash
.venv/Scripts/python -c "import collections, json; rows = json.load(open('live-metrics.samples.json'))['configs']['all']; bad = [r for r in rows if r['label'] == 'benign' and r['status'] == 'needs_human_review']; print(len(bad), collections.Counter(c for r in bad for c in r['reasons']))"
```

The 2026-11-19 run predates this file, so its 33/60 cannot be broken down; the next run can.

## The command

Git Bash on Windows (use `.venv/bin/` on Linux):

```bash
.venv/Scripts/python -m pip install ".[anthropic]"
export ANTHROPIC_API_KEY=...        # your key; never commit it or write it to a file
AISA_LIVE=1 .venv/Scripts/aisa eval --provider anthropic --max-calls 480 --out live-metrics.json
```

`480` covers 120 alerts x 4 configurations. The detector blocks some alerts before any call under
`detector-only` and `all`, so a clean run needs about 464 calls, which leaves a little room for
retries. When the budget runs out, the remaining alerts get the status `budget_exhausted`, count
as not attacked, and the command says the results are incomplete and exits with 3; run again
into a new file with a higher `--max-calls`. Exit codes: `0` complete, `3` budget hit, `2` a
guard or setup error (nothing was called), `1` internal error.

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
