# ai-security-assistant

A command-line assistant that triages synthetic SOC alerts with an LLM. The point of the
project is the defense layer around the model: alert fields such as hostnames, user names,
URLs and log messages are attacker-controlled, so they are treated as untrusted data and
checked for indirect prompt injection before and after the model sees them. The assistant
only recommends; it never executes anything. All data is synthetic.

Status: in development (Phase 4 of 7).

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

License: MIT, see [LICENSE](LICENSE).
