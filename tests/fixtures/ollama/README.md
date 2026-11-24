# Ollama fixtures

Reply bodies for `tests/test_ollama_provider.py` and `tests/test_cli_ollama.py`. Tests replay them
through an injected fake transport; nothing here is fetched and no socket is opened (CLAUDE.md).
The model name inside them is data (the model that produced the reply), so the gate's
"default model literal only in its constant" check skips this folder.

## Which fixtures are real and which are synthetic

| File | Real or synthetic | What it is |
|------|-------------------|------------|
| `chat_real_status_logon.json` | **real, byte-exact** | The owner's raw `/api/chat` capture from the local Ollama: qwen3:8b, `stream=false`, `think=false`, `format="json"`, `temperature=0`, `seed=42`. The file is copied unchanged (no trailing newline). It is the only recorded envelope here, and the only one with the field `prompt_eval_cached_count`. |
| `chat_hallucination_4625.json` | synthetic envelope, **real excerpt** | The first observed hallucination (below), inside an envelope built from the documented fields. |
| `chat_wazuh_1.json` .. `_3.json` | synthetic | Complete `/api/chat` replies whose content is the well-behaved triage of the three alerts in `tests/fixtures/wazuh/alerts.jsonl`, in order. The contents come from the offline mock, not from a model. |
| `chat_think.json` | synthetic | Content that starts with a `<think>` block before the JSON: a strict-parse failure. |
| `chat_length.json` | synthetic | `done_reason: "length"`, content cut off mid-object. |
| `version.json`, `tags.json` | synthetic | `GET /api/version` and `GET /api/tags` answers (the health check), shaped after the Ollama API documentation. |

The synthetic envelopes follow the documented fields, so their timings and counts are
placeholders. Tests rely on field names only, and `test_the_provider_tolerates_unknown_envelope_fields`
proves that extra fields such as `prompt_eval_cached_count` change nothing.

## The two observed qwen3:8b hallucinations (inputs for Phase 10)

Phase 10 turns these into validator regressions. Nothing here is validator logic; the tests only
pin that the recorded text is what it is and that the provider hands it over untouched.

Ground truth (the table in `data/windows_kb.json` once Phase 9 adds it): Logon Type 10 is
RemoteInteractive (2 is Interactive, 3 is Network); `0xC000006A` is a correct user name with a bad
password; a user name that does not exist is `0xC0000064`; "logon right not granted" is
`0xC000015B`; a locked-out account is `0xC0000234` (with Event 4740); Event 4625 never records the
attempted password; `0xC000006D` is the generic Status and the specific cause is in Sub Status.

1. **`chat_hallucination_4625.json`** (prose; prompt "Explain Windows Event ID 4625 and what a
   brute-force pattern looks like", think off). Only the excerpt lines the owner captured exist,
   so the content is those lines verbatim and nothing else. Wrong claims: Logon Type 10 as
   "Interactive"; `0xC000006A` as "the requested logon right was not granted"; a locked-out
   account as "logon right not granted"; `0xC000006D` as a bare "Incorrect password".
2. **`chat_real_status_logon.json`** (a JSON object with the keys `status_meaning` and
   `logon_type_10`, so valid JSON but not the triage schema). Wrong claims: `0xC000006A` means
   "the user account is invalid ... or the account does not exist" (truth: the account exists and
   the password is wrong; a nonexistent user is `0xC0000064`), and Logon Type 10 is "a network
   logon" (truth: RemoteInteractive, for example RDP; network is 3).
