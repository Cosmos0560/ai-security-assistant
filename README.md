# ai-security-assistant

A command-line assistant that triages synthetic SOC alerts with an LLM. The point of the
project is the defense layer around the model: alert fields such as hostnames, user names,
URLs and log messages are attacker-controlled, so they are treated as untrusted data and
checked for indirect prompt injection before and after the model sees them. The assistant
only recommends; it never executes anything. All data is synthetic.

Status: in development (Phase 5 of 7).

The plan, decisions and phases are in [PLAN.md](PLAN.md).

## Providers

`aisa triage <file> --provider {mock,mock-naive,anthropic} --max-calls N` (default `mock`,
20 calls). The two mocks are offline and deterministic. The real provider is optional:

- install the extra with `pip install ".[anthropic]"`;
- the key comes only from the `ANTHROPIC_API_KEY` environment variable, never from a file or a
  flag, and is never printed or logged;
- the model is `AISA_ANTHROPIC_MODEL` (default `claude-haiku-5-5`);
- the endpoint is always passed explicitly (`https://api.anthropic.com`). An inherited
  `ANTHROPIC_BASE_URL` is ignored on purpose, so a stray variable cannot send alert data and the
  key to another host. Set `AISA_ANTHROPIC_BASE_URL` (https only) to change it deliberately;
- every attempt, retries included, counts against `--max-calls`.

Tests never call the API. The one live test needs `AISA_LIVE=1` and a key, and CI sets neither.

## Reports and exit codes

`aisa triage <file> [--out-dir reports/] [--include-raw] [--force]` runs every defense
(sanitize + wrap, detector, validator) and writes `report.md` and `report.json`. It refuses to
overwrite them without `--force`. Untrusted values are stripped of control characters, capped
and Markdown-escaped; raw model text never appears in `report.md`, and in `report.json` only
with `--include-raw`. The terminal shows counts and paths only. Exit codes: `0` all triaged,
`3` any alert needs human review or hit the call budget, `2` usage or input error, `1` internal
error. There is no flag that turns a defense off.

## What it can't do (so far)

- Secrets that only high entropy would reveal are not detected: the output secret scan uses
  the vendored scanner's pattern rules with entropy detection off.
- A forced severity UPGRADE is accepted by design. The validator rejects a severity below the
  floor taken from the source tool's own severity (D33), but an injected "mark this critical"
  passes; it costs analyst attention and hides nothing. An alert whose source severity cannot
  be mapped has no floor.
- Results with the mock providers measure the pipeline's mechanics only, not how a real model
  behaves under injection.

License: MIT, see [LICENSE](LICENSE).
