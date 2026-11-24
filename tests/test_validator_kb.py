"""Validator check 9 (D42): one pass and one fail case per reason code, how mentions and clauses
are read, the grounded echo of the trusted reference block, and the wiring into the validator and
the pipeline.

Every Windows name, meaning and alias here is read from ``data/windows_kb.json``; only codes (the
table's keys) appear as literals. Text that claims a password is built at runtime.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any

import pytest

from ai_security_assistant.detector.canary import new_canary
from ai_security_assistant.eval.dataset import load_dataset
from ai_security_assistant.eval.runner import run_eval
from ai_security_assistant.kb import (
    KnowledgeBase,
    PatternFact,
    ReferenceFacts,
    load_kb,
    parse_kb,
    reference_facts,
)
from ai_security_assistant.kb.patterns import batch_patterns
from ai_security_assistant.models import Alert
from ai_security_assistant.pipeline import DefenseConfig, Status, run_pipeline
from ai_security_assistant.prompt import render_reference_block
from ai_security_assistant.providers.base import CallBudget
from ai_security_assistant.providers.mock import WellBehavedMock
from ai_security_assistant.triage import TriageResult, TriageStatus, parse_triage
from ai_security_assistant.validator import Verdict, validate
from ai_security_assistant.validator import kb as check9
from ai_security_assistant.validator.kb import RULES, scan

KB = load_kb()
EVENTS, LOGON, STATUS = KB.events, KB.logon_types, KB.statuses
SPRAY = KB.patterns.password_spraying.technique
BRUTE = KB.patterns.brute_force.technique
NOW = datetime(2026, 8, 10, 9, 0, 0, tzinfo=UTC)
CANARY = new_canary("s")
NOUN = KB.events["4625"].never_records[0].split()[-1]  # the thing 4625 never records


def alert(**fields: Any) -> Alert:
    base: dict[str, Any] = {
        "source": "wazuh",
        "timestamp": NOW,
        "id": "a-1",
        "rule_id": "60122",
        "severity_raw": "5",
    }
    return Alert(**{**base, **fields})


def kb_with(mutate: Any) -> KnowledgeBase:
    """A table changed by ``mutate`` (a function over the parsed JSON document)."""
    text = resources.files("ai_security_assistant").joinpath("data", "windows_kb.json")
    document = json.loads(text.read_text(encoding="utf-8"))
    mutate(document)
    return parse_kb(json.dumps(document))


def pattern_fact(name: str) -> PatternFact:
    rules = KB.patterns
    technique = {"password_spraying": SPRAY, "brute_force": BRUTE}.get(name)
    meaning = getattr(rules, name).meaning
    return PatternFact(name, technique, meaning, rules.window_seconds, 4, 1, 4)  # type: ignore[arg-type]


# ---------------------------------------------------------------- one pass and one fail per code

FAILED_LOGON = {
    "event_id": "4625",
    "logon_type": "10",
    "status": "0xc000006d",
    "sub_status": "0xc000006a",
}


@pytest.mark.parametrize(
    ("rule", "failing", "passing", "fields"),
    [
        ("unknown_event_id", "event 9999 seen", "event 4625 seen", FAILED_LOGON),
        ("unknown_logon_type", "logon type 12 seen", "logon type 10 seen", FAILED_LOGON),
        ("unknown_status", "status 0xC0000999", "status 0xC000006D", FAILED_LOGON),
        ("ungrounded_event_id", "event 4740 seen", "event 4625 seen", FAILED_LOGON),
        ("ungrounded_logon_type", "logon type 3 seen", "logon type 10 seen", FAILED_LOGON),
        ("ungrounded_status", "status 0xC0000064", "sub status 0xC000006A", FAILED_LOGON),
        (
            "contradiction_event_id",
            f"event 4625 ({EVENTS['4740'].aliases[0]})",
            f"event 4625 ({EVENTS['4625'].aliases[0]})",
            FAILED_LOGON,
        ),
        (
            "contradiction_logon_type",
            f"logon type 10 ({LOGON['2'].name})",
            f"logon type 10 ({LOGON['10'].name})",
            FAILED_LOGON,
        ),
        (
            "contradiction_status",
            f"0xC000006A: {STATUS['0xC000015B'].aliases[0]}",
            f"0xC000006A: {STATUS['0xC000006A'].aliases[0]}",
            FAILED_LOGON,
        ),
        (
            "not_recorded_claim",
            f"the attempted {NOUN} was " + "hunter" + "2",
            f"event 4625 never records the attempted {NOUN}",
            FAILED_LOGON,
        ),
    ],
)
def test_each_code_rule_has_a_fail_and_a_pass(
    rule: str, failing: str, passing: str, fields: dict[str, str]
) -> None:
    subject = alert(**fields)
    assert scan([failing], subject) == [rule]
    assert scan([passing], subject) == []


@pytest.mark.parametrize(
    ("pattern", "technique", "expected"),
    [
        ("password_spraying", BRUTE, ["contradiction_pattern"]),
        ("password_spraying", SPRAY, []),
        ("brute_force", SPRAY, ["contradiction_pattern"]),
        ("brute_force", BRUTE, []),
        ("undetermined", SPRAY, ["unsupported_pattern"]),
        ("undetermined", BRUTE, ["unsupported_pattern"]),
        ("undetermined", "T1110", []),  # the parent technique is not a pattern claim
        ("password_spraying", "T1059", []),
        ("brute_force", f" {SPRAY.lower()} ", ["contradiction_pattern"]),  # case and spaces
    ],
)
def test_the_technique_must_agree_with_the_batch_pattern(
    pattern: str, technique: str, expected: list[str]
) -> None:
    fact = pattern_fact(pattern)
    assert scan([], alert(event_id="4625"), technique=technique, pattern=fact) == expected


def test_no_pattern_fact_or_no_technique_is_not_checked() -> None:
    assert scan([], alert(event_id="4625"), technique=BRUTE, pattern=None) == []
    assert scan([], alert(), technique=SPRAY) == []
    assert scan([], alert(), technique=None, pattern=pattern_fact("brute_force")) == []


def test_rules_are_reported_once_each_in_a_fixed_order() -> None:
    text = f"event 9999. logon type 3. status 0xC0000064. the attempted {NOUN} is x"
    found = scan(
        [text, text], alert(**FAILED_LOGON), technique=SPRAY, pattern=pattern_fact("brute_force")
    )
    assert found == [
        "unknown_event_id",
        "ungrounded_logon_type",
        "ungrounded_status",
        "contradiction_pattern",
        "not_recorded_claim",
    ]
    assert found == [rule for rule in RULES if rule in found]
    assert len(RULES) == len(set(RULES)) == 12


# ---------------------------------------------------------------- what counts as a mention


@pytest.mark.parametrize(
    "text",
    [
        "Event ID: 4625",
        "EventID 4625",
        'eventID":"4625',
        "EID 4625",
        "event id 4625",
        "events 4625",
        "Windows Event (4625)",
        "**Event** 4625",
    ],
)
def test_event_id_mentions_need_their_anchor(text: str) -> None:
    assert scan([text], alert(event_id="4624")) == ["ungrounded_event_id"]
    assert scan([text], alert(event_id="4625")) == []


@pytest.mark.parametrize(
    "text",
    [
        "connection to port 4625",
        "4625 failures in 2026",
        "rule 60122 fired",
        "event on 2025-03-01 at 10:30",
        "event 2025-03-01",
        "event 10:30",
        "event 192.0.2.66",
        "Wazuh event 1786266370",
        "prevent 4625",
        "logon type 123",
    ],
)
def test_bare_numbers_ports_years_dates_and_long_numbers_are_not_codes(text: str) -> None:
    assert scan([text], alert()) == []


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("event 04625", "unknown_event_id"),
        ("logon type 03", "unknown_logon_type"),
        ("logon type 0", "unknown_logon_type"),
    ],
)
def test_a_padded_code_is_unknown(text: str, rule: str) -> None:
    assert scan([text], alert(**FAILED_LOGON)) == [rule]


def test_a_status_is_any_8_digit_hex_token_in_any_case() -> None:
    subject = alert(**FAILED_LOGON)
    assert scan(["0xc000006a", "`0XC000006A`"], subject) == []
    assert scan(["0xC000006A1", "x0xC0000064", "0xC00000"], subject) == []
    assert scan(["(0xDEADBEEF)"], subject) == ["unknown_status"]


def test_a_code_in_the_alert_text_does_not_ground_it() -> None:
    subject = alert(message="Logon Type: 3, Status 0xC0000064, event 4740")
    assert scan(["logon type 3", "status 0xC0000064", "event 4740"], subject) == [
        "ungrounded_event_id",
        "ungrounded_logon_type",
        "ungrounded_status",
    ]


def test_a_logon_type_list_on_the_anchor_line_counts() -> None:
    row = f'| Logon Type | e.g. 3 for "{LOGON["3"].name}", 10 = {LOGON["2"].aliases[0]} |'
    assert scan([row], alert(logon_type="10")) == [
        "ungrounded_logon_type",
        "contradiction_logon_type",
    ]
    assert scan([row.replace(LOGON["2"].aliases[0], LOGON["10"].name)], alert(logon_type="3")) == [
        "ungrounded_logon_type"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "logon type 10 seen 3 for user bob",  # a list item must be followed by an alias
        f"logon type 10:\n3 for {LOGON['3'].name}",  # only on the anchor's own line
        f"3 for {LOGON['3'].name}",  # no anchor at all
        f"logon type 10 at 192.0.2.3 ({LOGON['10'].name})",  # not inside an address
    ],
)
def test_list_items_off_the_anchor_line_or_without_an_alias_are_not_mentions(text: str) -> None:
    assert scan([text], alert(logon_type="10")) == []


# ---------------------------------------------------------------- clauses and aliases


def test_longest_alias_wins() -> None:
    remote = next(a for a in LOGON["10"].aliases if " " in a and LOGON["2"].aliases[0] in a)
    assert scan([f"logon type 10 ({remote})"], alert(logon_type="10")) == []
    cleartext = next(a for a in LOGON["8"].aliases if LOGON["3"].aliases[0] in a and " " in a)
    assert scan([f"logon type 8 ({cleartext})"], alert(logon_type="8")) == []
    assert scan([f"logon type 3 ({cleartext})"], alert(logon_type="3")) == [
        "contradiction_logon_type"
    ]


def test_an_alias_inside_a_longer_word_is_not_an_alias() -> None:
    word = LOGON["5"].aliases[0] + "s"  # "...s": a different word
    assert scan([f"logon type 10 ({word})"], alert(logon_type="10")) == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("logon type 10 (rdp). {other} sessions are common.", []),
        ("logon type 10 (rdp); {other}", []),
        ("logon type 10 (rdp)!\n{other}", []),
        ("logon type 10\n{other}", []),
        ("logon type 10 e.g. {other}", ["contradiction_logon_type"]),
        ("logon type 10, {other}", ["contradiction_logon_type"]),
        ("logon type 10 ... {other}", ["contradiction_logon_type"]),  # an ellipsis is no end
        ("logon type 10 … {other}", ["contradiction_logon_type"]),
        ("logon type 10 (rdp)\r\n{other}", []),
        ("logon type 10 " + "x" * 250 + " {other}", []),  # past the clause cap
        ("logon type 10 and logon type 2 ({other})", ["ungrounded_logon_type"]),  # next code
    ],
)
def test_the_clause_ends_at_a_sentence_end_the_next_code_or_the_cap(
    text: str, expected: list[str]
) -> None:
    filled = text.replace("rdp", LOGON["10"].aliases[-1]).format(other=LOGON["2"].aliases[0])
    assert scan([filled], alert(logon_type="10")) == expected


@pytest.mark.parametrize(
    ("opener", "expected"),
    [
        ("This error code means", ["contradiction_status"]),
        ("This code means", ["contradiction_status"]),
        ("That status means", ["contradiction_status"]),
        ("The value means", ["contradiction_status"]),
        ("It means", ["contradiction_status"]),
        ("The account", []),  # not a back-reference
        ("Itself", []),
    ],
)
def test_a_back_reference_carries_the_clause_into_one_more_sentence(
    opener: str, expected: list[str]
) -> None:
    claim = STATUS["0xC0000064"].aliases[0]
    subject = alert(**FAILED_LOGON)
    assert scan([f"Sub Status 0xC000006A was logged. {opener} {claim}."], subject) == expected
    # Only one sentence more.
    assert scan([f"Sub Status 0xC000006A was logged. It is common. {claim}."], subject) == []


def test_a_clause_that_reaches_the_next_code_has_no_continuation() -> None:
    subject = alert(**FAILED_LOGON)
    assert scan(["0xC000006A\n0xC000006A"], subject) == []
    assert scan(["0xC000006A " + "y" * 300], subject) == []


def test_tables_are_compared_separately() -> None:
    # A status alias next to a logon type is not a logon-type contradiction.
    assert (
        scan([f"logon type 10 ({STATUS['0xC0000234'].aliases[0]})"], alert(logon_type="10")) == []
    )


# ---------------------------------------------------------------- never-records claims


@pytest.mark.parametrize(
    "claim",
    [
        "the attempted {n} was guessed",
        "The attempted {n} is shown",
        "the {n} entered was weak",
        "the {n}s tried were common",
        "each attempt used a different {n}",
        "Each logon uses a new {n}",
        "the event shows the {n}",
        "The log records the attempted {n}",
        "this entry contains a {n}",
        "the logged {n} was short",
        "the recorded {n}s were reused",
    ],
)
def test_claims_that_the_log_holds_what_it_never_records_fail(claim: str) -> None:
    assert scan([claim.format(n=NOUN)], alert(event_id="4625")) == ["not_recorded_claim"]


@pytest.mark.parametrize(
    "claim",
    [
        "the attacker is trying different {n}s",
        "Different {n}s are tried in sequence.",  # pinned: passes on its own (blind spot)
        "event 4625 never records the attempted {n}",
        "the event does not record the {n}",
        "the event shows the {n} policy was applied",
        "the event shows the {n} has expired",
        "many {n}s against one account",
    ],
)
def test_attacker_behaviour_and_correct_statements_pass(claim: str) -> None:
    assert scan([claim.format(n=NOUN)], alert(event_id="4625")) == []


def test_the_never_records_rule_needs_an_event_that_never_records_something() -> None:
    claim = f"the attempted {NOUN} was x"
    assert scan([claim], alert(event_id="4624")) == []  # its never_records list is empty
    assert scan([claim], alert(event_id="9999")) == []  # not in the table
    assert scan([claim], alert()) == []


# ---------------------------------------------------------------- the grounded echo


def reference_text(subject: Alert, pattern: PatternFact | None = None, sep: str = "\n") -> str:
    facts = reference_facts(subject, pattern)
    assert facts is not None
    lines = render_reference_block(facts).splitlines()[1:-1]
    return sep.join(line.removeprefix("- ") for line in lines)


@pytest.mark.parametrize("sep", ["\n", " "])
@pytest.mark.parametrize(
    "fields",
    [
        FAILED_LOGON,
        {"event_id": "4740"},
        {"event_id": "4625", "status": "0xc0000234", "logon_type": "2"},
        {"event_id": "4624", "logon_type": "8"},
        {"event_id": "4624", "logon_type": "9"},
        {"event_id": "4624", "logon_type": "11"},
    ],
)
def test_a_faithful_echo_of_the_reference_block_passes(fields: dict[str, str], sep: str) -> None:
    subject = alert(**fields)
    for name in ("password_spraying", "brute_force", "undetermined"):
        pattern = pattern_fact(name)
        assert scan([reference_text(subject, pattern, sep)], subject, pattern=pattern) == []


def test_an_echo_counts_only_next_to_its_own_code() -> None:
    meaning = STATUS["0xC000006A"].meaning
    both = alert(status="0xc0000064", sub_status="0xc000006a")
    assert scan([f"0xC0000064: {meaning}"], both) == ["contradiction_status"]
    assert scan([f"0xC000006A: {meaning}"], both) == []
    assert scan([meaning], both) == []  # no code at all
    only_6a = alert(sub_status="0xc000006a")
    assert scan([f"0xC0000064: {meaning}"], only_6a) == [
        "ungrounded_status",
        "contradiction_status",
    ]
    # A paraphrase is never an echo.
    assert scan([f"0xC0000064: {STATUS['0xC000006A'].aliases[0]}"], both) == [
        "contradiction_status"
    ]


def test_an_echo_of_an_entry_the_alert_does_not_have_is_scanned() -> None:
    assert scan([f"0xC000006A: {STATUS['0xC0000064'].meaning}"], alert(**FAILED_LOGON)) == [
        "contradiction_status"
    ]


def test_an_echo_next_to_a_code_of_another_kind_is_scanned_normally() -> None:
    subject = alert(event_id="4625", status="0xc0000234")
    assert scan([f"event 4625: {STATUS['0xC0000234'].meaning}"], subject) == []
    assert scan(
        [f"logon type 10 then {STATUS['0xC0000234'].meaning}"], alert(status="0xc0000234")
    ) == ["ungrounded_logon_type"]


def test_an_echo_before_a_wrong_code_in_parentheses_is_a_contradiction() -> None:
    """Phase 10b: the meaning BEFORE a code in parentheses is a claim about that code (this
    was a Phase 10 known limit). Before its own code it is a grounded echo."""
    both = alert(status="0xc0000064", sub_status="0xc000006a")
    meaning = STATUS["0xC000006A"].meaning.rstrip(".")
    assert scan([f"{meaning} (0xC0000064)."], both) == ["contradiction_status"]
    assert scan([f"{meaning} (0xC000006A)."], both) == []
    assert scan([f"{meaning} (0xC000006A)."], both, echo=False) == []


# ---------------------------------------------------------------- Phase 10b: meaning before code

S64, S6A, S234 = STATUS["0xC0000064"], STATUS["0xC000006A"], STATUS["0xC0000234"]

MEANING_FIRST_FAILS = [
    # "the user name does not exist (0xC000006A)"
    (f"the {S64.aliases[2]} (0xC000006A)", {"status": "0xc000006a"}, "contradiction_status"),
    # "password is wrong (0xC0000064)"
    (f"{S6A.aliases[3]} (0xC0000064)", {"status": "0xc0000064"}, "contradiction_status"),
    # "interactive logon (logon type 10)"
    (
        f"{LOGON['2'].aliases[0]} logon (logon type 10)",
        {"logon_type": "10"},
        "contradiction_logon_type",
    ),
    # "account was locked out (0xC000006A)"
    (
        f"account was {S234.aliases[3]} (0xC000006A)",
        {"status": "0xc000006a"},
        "contradiction_status",
    ),
    # "failed logon (event 4624)"
    (f"{EVENTS['4625'].aliases[0]} (event 4624)", {"event_id": "4624"}, "contradiction_event_id"),
]

MEANING_FIRST_PASSES = [
    (f"{S6A.aliases[0]} (0xC000006A)", {"status": "0xc000006a"}),  # "bad password (...)"
    (f"{S64.aliases[0]} (0xC0000064)", {"status": "0xc0000064"}),  # "no such user (...)"
    (f"{LOGON['10'].aliases[3]} session (logon type 10)", {"logon_type": "10"}),  # "RDP session"
    (f"{S234.aliases[1]} (0xC0000234)", {"status": "0xc0000234"}),  # "account locked out (...)"
    (f"{EVENTS['4625'].aliases[0]} (event 4625)", {"event_id": "4625"}),
]


@pytest.mark.parametrize(("text", "fields", "rule"), MEANING_FIRST_FAILS)
def test_a_wrong_meaning_before_a_code_is_a_contradiction(
    text: str, fields: dict[str, str], rule: str
) -> None:
    assert scan([text], alert(**fields)) == [rule]
    assert scan([text.upper()], alert(**fields)) == [rule]


@pytest.mark.parametrize(("text", "fields"), MEANING_FIRST_PASSES)
def test_the_right_meaning_before_a_code_passes(text: str, fields: dict[str, str]) -> None:
    assert scan([text], alert(**fields)) == []


@pytest.mark.parametrize(
    "joint",
    [" - ", " -- ", " – ", "—", " (status ", " (SubStatus: ", " - error code ", " (code "],
)
def test_a_dash_or_a_labelled_parenthesis_also_joins(joint: str) -> None:
    assert scan([f"{S6A.aliases[1]}{joint}0xC0000064"], alert(status="0xc0000064")) == [
        "contradiction_status"
    ]


@pytest.mark.parametrize("joint", [": ", " ", " = ", ", status "])
def test_a_colon_or_a_bare_space_does_not_join(joint: str) -> None:
    """Label form ("wrong password: 0x...") and plain lists are not read backwards: residual
    blind spot, recorded in the phase report."""
    assert scan([f"{S6A.aliases[1]}{joint}0xC0000064"], alert(status="0xc0000064")) == []


@pytest.mark.parametrize(
    "before",
    [
        "{wrong}. Then ",  # a sentence end
        "{wrong}\nthen ",  # a line break
        "{wrong}, then ",  # a comma
        "{wrong}: then ",  # a colon
        "({wrong}) then ",  # a closing parenthesis
        "{wrong} event 4625 then ",  # a previous code mention
    ],
)
def test_the_clause_before_stops_at_its_boundary(before: str) -> None:
    subject = alert(event_id="4625", status="0xc0000064")
    text = before.format(wrong=S6A.aliases[1]) + S64.aliases[0] + " (0xC0000064)"
    assert scan([text], subject) == []


def test_the_clause_before_is_capped() -> None:
    subject = alert(status="0xc0000064")
    far = f"{S6A.aliases[1]} " + "x" * check9.MAX_CLAUSE_CHARS + " (0xC0000064)"
    assert scan([far], subject) == []
    near = f"{S6A.aliases[1]} " + "x" * (check9.MAX_CLAUSE_CHARS - 40) + " (0xC0000064)"
    assert scan([near], subject) == ["contradiction_status"]


def test_back_clause_reads_only_the_joined_clause() -> None:
    matchers = check9._matchers(KB)
    words = S6A.aliases[0]
    text = check9.kb_text(f"a, {words} (logon type 10)")
    (mention,) = check9.mentions(text, matchers)
    assert text[mention.anchor : mention.start] == "logon type "
    assert check9.back_clause(text, mention, 0) == f" {words} "
    assert check9.back_clause(text, mention, mention.anchor) == ""
    bare = check9.kb_text(f"{words} logon type 10")
    (plain,) = check9.mentions(bare, matchers)
    assert check9.back_clause(bare, plain, 0) == ""


def test_without_the_exemption_the_echo_is_scanned_as_a_plain_claim() -> None:
    both = alert(status="0xc0000064", sub_status="0xc000006a")
    meaning = STATUS["0xC000006A"].meaning
    assert scan([f"0xC000006A: {meaning}"], both, echo=False) == []
    swapped = kb_with(
        lambda d: d["statuses"]["0xC000006A"].update(meaning="See 0xC0000064. Then fail.")
    )
    text = "0xC000006A: See 0xC0000064. Then fail."
    assert scan([text], alert(sub_status="0xc000006a"), kb=swapped) == []
    assert scan([text], alert(sub_status="0xc000006a"), kb=swapped, echo=False) == [
        "ungrounded_status"
    ]


def test_an_empty_meaning_sentence_is_not_an_echo_phrase() -> None:
    odd = kb_with(lambda d: d["statuses"]["0xC000006A"].update(meaning="Fails. ."))
    patterns = check9.echo_patterns(alert(sub_status="0xc000006a"), odd)
    assert all(regex.pattern for regex, _kind, _code in patterns)
    assert scan(["0xC000006A: fails."], alert(sub_status="0xc000006a"), kb=odd) == []


def test_an_alert_code_missing_from_the_table_gives_no_echo() -> None:
    assert check9.echo_patterns(alert(status="0xc0000999", logon_type="12"), KB) == []


def test_blank_keeps_whitespace_and_sentence_ends() -> None:
    text = "ab. c;d"
    assert check9.blank(text, [check9.Echo("status", "0x", 0, len(text))]) == "\x00\x00. \x00;\x00"


def test_matchers_are_rebuilt_for_another_table() -> None:
    other = kb_with(lambda d: d["logon_types"]["2"]["aliases"].append("desk logon"))
    assert scan(["logon type 10 (desk logon)"], alert(logon_type="10"), kb=other) == [
        "contradiction_logon_type"
    ]
    assert scan(["logon type 10 (desk logon)"], alert(logon_type="10")) == []
    assert scan(["logon type 10 (desk logon)"], alert(logon_type="10"), kb=other) == [
        "contradiction_logon_type"
    ]


# ---------------------------------------------------------------- the validator and the pipeline


def result_for(document: dict[str, Any]) -> TriageResult:
    raw = json.dumps(document)
    output, reason = parse_triage(raw)
    assert output is not None, reason
    return TriageResult(TriageStatus.OK, output=output, raw_text=raw)


def mock_reply(subject: Alert) -> dict[str, Any]:
    from ai_security_assistant.prompt import build_user_prompt
    from ai_security_assistant.sanitize import sanitize_alert
    from ai_security_assistant.wrap import new_nonce

    sanitized, _report = sanitize_alert(subject)
    user = build_user_prompt(sanitized, new_nonce("s"), None)
    document: dict[str, Any] = json.loads(WellBehavedMock(CallBudget(1)).complete("s", user))
    return document


def test_check_9_runs_inside_the_validator_with_the_pattern() -> None:
    subject = alert(**FAILED_LOGON, src_ip_raw="192.0.2.66", target_user="svc-test")
    document = {**mock_reply(subject), "mitre_technique": BRUTE}
    accepted = validate(result_for(document), subject, CANARY)
    assert accepted.verdict is Verdict.ACCEPTED
    rejected = validate(result_for(document), subject, CANARY, pattern_fact("password_spraying"))
    assert rejected.verdict is Verdict.NEEDS_HUMAN_REVIEW
    assert rejected.reasons == ("kb.contradiction_pattern",)
    claim = {**mock_reply(subject), "summary": f"logon type 10 ({LOGON['2'].name})"}
    assert validate(result_for(claim), subject, CANARY).reasons == ("kb.contradiction_logon_type",)


class TechniqueProvider:
    """The well-behaved mock, with a fixed technique."""

    name = "technique-mock"

    def __init__(self, budget: CallBudget, technique: str) -> None:
        self.inner = WellBehavedMock(budget)
        self.technique = technique

    def complete(self, system: str, user: str) -> str:
        document = json.loads(self.inner.complete(system, user))
        document["mitre_technique"] = self.technique
        return json.dumps(document)


def spraying_batch() -> list[Alert]:
    return [
        alert(
            id=f"a-{index}",
            event_id="4625",
            src_ip_raw="192.0.2.66",
            target_user=f"user{index}",
            timestamp=NOW + timedelta(seconds=index),
        )
        for index in range(KB.patterns.password_spraying.min_distinct_users)
    ]


@pytest.mark.parametrize(
    ("config", "status"),
    [
        (DefenseConfig.VALIDATOR_ONLY, Status.NEEDS_HUMAN_REVIEW),
        (DefenseConfig.ALL, Status.NEEDS_HUMAN_REVIEW),
        (DefenseConfig.DETECTOR_ONLY, Status.TRIAGED),
        (DefenseConfig.NONE, Status.TRIAGED),
    ],
)
def test_the_pipeline_gives_the_batch_pattern_to_the_validator(
    config: DefenseConfig, status: Status
) -> None:
    batch = spraying_batch()
    assert {fact.pattern for fact in batch_patterns(batch).values()} == {"password_spraying"}
    budget = CallBudget(len(batch))
    result = run_pipeline(batch, TechniqueProvider(budget, BRUTE), budget, config=config, seed="s")
    assert {outcome.status for outcome in result.outcomes} == {status}
    if status is Status.NEEDS_HUMAN_REVIEW:
        assert {outcome.reasons for outcome in result.outcomes} == {("kb.contradiction_pattern",)}
    budget = CallBudget(len(batch))
    agreeing = run_pipeline(
        batch, TechniqueProvider(budget, SPRAY), budget, config=config, seed="s"
    )
    assert {outcome.status for outcome in agreeing.outcomes} == {Status.TRIAGED}


def test_the_reference_facts_render_from_the_same_table() -> None:
    facts = reference_facts(alert(**FAILED_LOGON))
    assert isinstance(facts, ReferenceFacts) and facts.kb_version == KB.kb_version


@pytest.fixture(scope="module")
def eval_run() -> Any:
    return run_eval(load_dataset())


def test_check_9_never_fires_on_the_120_alert_set(eval_run: Any) -> None:
    """The 120 set has no Windows keys, and neither mock names a Windows code, so check 9 adds
    no review anywhere: the README mock table cannot move (Phase 10 exit criterion)."""
    for sample in eval_run.samples:
        assert check9.own_codes(sample.alert) == {
            "event_id": set(),
            "logon_type": set(),
            "status": set(),
        }
    runs = [*eval_run.naive, eval_run.well_behaved_all]
    reasons = [reason for run in runs for outcome in run.outcomes for reason in outcome.reasons]
    assert reasons  # the other checks do fire
    assert not [reason for reason in reasons if reason.startswith("kb.")]
