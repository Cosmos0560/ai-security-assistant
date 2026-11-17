# Security policy

## Scope

In scope: the code in this repository, in particular anything that lets attacker-controlled alert
content get past the defense layer in a way the documentation does not already list:

- a forced severity DOWNGRADE, an off-allowlist action, a canary leak, an ungrounded indicator or
  non-JSON output that reaches a `triaged` verdict with every defense on;
- text in an alert or a model reply that is rendered live in `report.md` or the terminal (a
  link, image, HTML, escape sequence or bidi control);
- any path by which the tool executes something, writes outside its output folder, or exposes the
  API key;
- a way to make the gate pass on code that breaks its rules.

Out of scope, because they are documented limits (README "What it can't do",
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)): attacker-chosen text inside a valid summary
(`summary_manipulation`), forced severity upgrades, paraphrased or non-English injections that
get past the pattern detector but are still stopped by the validator, entropy-only secrets, and
the behaviour of a third-party model. Vulnerabilities in the vendored secret-scanner belong to
[secret-scanner](https://github.com/Cosmos0560/secret-scanner) as well; report them here if they
affect this tool.

Supported version: the latest release (1.0.x).

## Reporting privately

Please do not open a public issue for a vulnerability. Use GitHub's private vulnerability
reporting: on the repository page, open the **Security** tab and choose **Report a
vulnerability**. Include the affected version, a synthetic input that reproduces the problem,
what you expected and what happened. You can expect an acknowledgement within a week.

## Synthetic data only

This project uses synthetic data only, and reports must too:

- IP addresses only from the documentation ranges (RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`; IPv6 `2001:db8::/32`); domains only `example.com` or `.test`;
- user names, never email addresses; obviously fake hashes; no real secrets, keys or tokens;
- no real alerts, logs, indicators or personal data, and no working attack code against real
  systems.

Never include an API key in a report. If you used the live provider to find the problem, say
which model, not which key.
