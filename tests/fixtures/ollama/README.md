# Ollama fixtures

Reply bodies for `tests/test_ollama_provider.py` and `tests/test_cli_ollama.py`. Tests replay them
through an injected fake transport; nothing here is fetched and no socket is opened (CLAUDE.md).
The model name inside them is data (the model that produced the reply), so the gate's
"default model literal only in its constant" check skips this folder.

| File | What it is |
|------|------------|
| `version.json`, `tags.json` | `GET /api/version` and `GET /api/tags` answers (the health check) |
| `chat_wazuh_1.json` .. `_3.json` | complete `/api/chat` replies whose content is the well-behaved triage of the three alerts in `tests/fixtures/wazuh/alerts.jsonl`, in order |
| `chat_think.json` | content that starts with a `<think>` block before the JSON: a strict-parse failure |
| `chat_length.json` | `done_reason: "length"`, content cut off mid-object |
| `chat_hallucination_4625.json` | the observed qwen3:8b hallucination (below) |

## Provenance, stated plainly

* **Observed hallucination.** `chat_hallucination_4625.json` holds the excerpt the owner captured
  from qwen3:8b (think off, prompt "Explain Windows Event ID 4625 and what a brute-force pattern
  looks like"). Only the excerpt lines exist, so the content is those lines verbatim and nothing
  else. It is prose, not triage JSON, so through the pipeline it is a parse failure today; Phase 10
  turns the wrong claims into validator regressions. Ground truth (the table in `data/windows_kb.json`
  once Phase 9 adds it): Logon Type 10 is RemoteInteractive (2 is Interactive); `0xC000006A` is a
  correct user name with a bad password; "logon right not granted" is `0xC000015B`; a locked-out
  account is `0xC0000234` (with Event 4740); Event 4625 never records the attempted password;
  `0xC000006D` is the generic Status and the specific cause is in Sub Status.
* **Envelope.** The surrounding `/api/chat` envelope (field names and types) follows the Ollama API
  documentation. The owner's raw capture of a full envelope was not available when this phase was
  written, so the timings and counts are plausible placeholders, and `chat_wazuh_*` contents come
  from the offline well-behaved mock, not from the model. Swap in the raw capture when it exists;
  the tests only rely on the field names.
