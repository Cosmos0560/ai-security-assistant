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

Guards, all checked before any call is made:

- `AISA_LIVE=1` must be set, and `ANTHROPIC_API_KEY` must hold a key (environment only, never a
  flag or file) with the `[anthropic]` extra installed;
- `--max-calls` is required; every attempt, retries included, spends one call;
- `--out` is required, must not exist yet (results are never overwritten) and its folder must
  exist;
- `--readme` is refused: the README table is mock-only and the gate's drift check would fail
  on live numbers anyway.

If the results file cannot be written after the run, the metrics are printed to stdout instead,
so a paid run is not lost.

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
and 600 output tokens. Another model costs proportionally more (for example, Claude Sonnet 5.5
lists at 20 times the Haiku 5.5 price, so its ceiling is about $4.40).

## Before the full run: a one-call check

Run the single live test first. It makes one call and costs a fraction of a cent:

```bash
AISA_LIVE=1 .venv/Scripts/python -m pytest -m live tests/live
```

Known risk, not verified here because no live call is ever made in development: the provider
sends `temperature=0` and forces the tool call with `tool_choice: {"type": "tool", ...}`.
Anthropic's current API reference says Claude Haiku 5.5 rejects non-default sampling values with
a 400, and some current models reject forced `tool_choice`. If the one-call check fails with a
`BadRequestError`, the provider request needs updating before the full run (a code change in
`providers/anthropic.py`, outside this document). Rejected requests are not billed, but each
attempt still spends one unit of `--max-calls`.
