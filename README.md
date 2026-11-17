# ai-security-assistant

A command-line assistant that triages synthetic SOC alerts with an LLM. The point of the
project is the defense layer around the model: alert fields such as hostnames, user names,
URLs and log messages are attacker-controlled, so they are treated as untrusted data and
checked for indirect prompt injection before and after the model sees them. The assistant
only recommends; it never executes anything. All data is synthetic.

Status: in development (Phase 2 of 7).

The plan, decisions and phases are in [PLAN.md](PLAN.md).

License: MIT, see [LICENSE](LICENSE).
