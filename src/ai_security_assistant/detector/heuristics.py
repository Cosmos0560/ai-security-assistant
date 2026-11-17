"""Heuristic injection scoring (D9, D10, D21): weighted, explainable rules in 8 categories.

Each rule has an id, a category, a weight and ONE regular expression. A rule fires at most once
per alert (its weight is added once, whatever number of fields match), and the fields it matched
are recorded. A category's score is the sum of its fired rules' weights, capped at
``CATEGORY_CAP`` so that one noisy category cannot drown out the rest. The total is the sum of
the category scores, and the decision is ``block`` at or above ``Thresholds.block``, ``flag`` at
or above ``Thresholds.flag`` and ``pass`` below (D10).

The result names rule ids and field names only. It never echoes attacker text.

ReDoS safety: every quantifier in every pattern is bounded, and a gap between words is always a
bounded run of non-word characters, so no pattern can backtrack exponentially or run away on a
long run of one character. ``tests/test_heuristics.py`` lints the pattern sources for unbounded
quantifiers and times a maximum-length adversarial field for each rule set.

These patterns are for detection only. They are deliberately NOT shared with the naive mock
provider (D16).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from ai_security_assistant.sanitize import SanitizedAlert, SanitizeReport, homoglyph_skeleton

CATEGORIES: Final = (
    "direct_override",
    "role_play",
    "delimiter_escape",
    "encoded_payload",
    "output_format_hijack",
    "ioc_bait",
    "prompt_exfiltration",
    "non_english",
)

Decision = Literal["pass", "flag", "block"]

CATEGORY_CAP: Final = 8.0
MAX_SCAN_CHARS: Final = 32_768


@dataclass(frozen=True)
class Thresholds:
    """Decision thresholds on the total score (D10)."""

    flag: float = 3.0
    block: float = 6.0

    def __post_init__(self) -> None:
        if not 0 < self.flag <= self.block:
            raise ValueError("thresholds must satisfy 0 < flag <= block")


DEFAULT_THRESHOLDS: Final = Thresholds()


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    pattern: re.Pattern[str]


# --- building blocks (all bounded) --------------------------------------------------------

_I: Final = re.IGNORECASE
S: Final = r"\W{1,4}"  # the gap between two words
_ART: Final = r"(?:(?:the|all|any|your|my|these|those|every|of|everything)" + S + r"){0,3}"
_FILL: Final = r"(?:\w{1,12}" + S + r"){0,3}?"
_FILL6: Final = r"(?:\w{1,12}" + S + r"){0,6}?"  # room for a dotted IP or a longer clause
_AP: Final = "['\u2018\u2019\u02bb\u02bc`\u00b4]?"  # Uzbek o' / g' / e' apostrophe variants


def _rule(rule_id: str, category: str, weight: float, *parts: str) -> Rule:
    """A rule whose pattern is the concatenation of ``parts`` (case-insensitive)."""
    return Rule(rule_id, category, weight, re.compile("".join(parts), _I))


_DIRECT_VERB: Final = r"(?:ignore|disregard|forget|override|bypass|discard|skip)"
_PREV: Final = r"(?:previous|prior|above|earlier|preceding|former|initial|foregoing)"
# Words that name the model's instructions (strong) versus words that also fit ordinary ops
# text such as "ignore the previous rules for this subnet" (weak).
_INSTR: Final = r"(?:instructions?|prompts?|guidelines|programming|directives)"
_INSTR_WEAK: Final = r"(?:rules|directions|commands|constraints|messages)"
_DO_NOT: Final = r"(?:do\W{1,3}not|don\W?t|never)"
_VERBS_REVEAL: Final = (
    r"(?:reveal|show|print|display|output|repeat|leak|tell|dump|echo|disclose|recite|expose"
    r"|include|append|embed)"
)

# The rule table is hand-laid-out: one rule per block, the pattern split at its alternations.
# fmt: off
RULES: Final[tuple[Rule, ...]] = (
    # --- direct override ---
    _rule(
        "DO-01", "direct_override", 6.0,
        r"\b", _DIRECT_VERB, S, _ART, _PREV, S, r"(?:\w{1,12}", S, r"){0,2}?", _INSTR,
    ),
    _rule(
        "DO-10", "direct_override", 4.0,
        r"\b", _DIRECT_VERB, S, _ART, _PREV, S, r"(?:\w{1,12}", S, r"){0,2}?", _INSTR_WEAK,
    ),
    _rule(
        "DO-02", "direct_override", 4.0,
        r"\b", _DIRECT_VERB, S, _ART,
        r"(?:system|safety|security|original|existing|developer)", S,
        r"(?:instructions?|prompts?|guidelines|programming|constraints|directives)",
    ),
    _rule(
        "DO-03", "direct_override", 4.0,
        r"\b", _DO_NOT, S, r"(?:follow|obey|heed|listen\W{1,3}to)", S, _ART,
        r"(?:previous|prior|earlier|above|original|system)", S, _INSTR,
    ),
    _rule(
        "DO-04", "direct_override", 3.0,
        r"\b(?:new|updated|revised|real|actual)\W{1,3}(?:instructions?|directives?|orders)\W{0,3}:",
    ),
    _rule(
        "DO-05", "direct_override", 3.0,
        r"\bfrom\W{1,3}now\W{1,3}on", S,
        r"(?:you|your|always|only|respond|reply|answer|act|ignore|classify|rate|mark)\b",
    ),
    _rule(
        "DO-06", "direct_override", 4.0,
        r"\b(?:you\W{1,3}(?:must|should|shall|will)|please|always|now)", S,
        r"(?:\w{1,12}", S, r"){0,5}?",
        r"(?:benign|harmless|false\W{1,3}positive|informational|not\W{1,3}malicious",
        r"|no\W{1,3}threat)\b",
    ),
    _rule(
        "DO-07", "direct_override", 3.0,
        r"\b(?:set|force|change|downgrade|lower|reduce)", S, r"(?:the", S, r")?",
        r"(?:severity|priority|risk|confidence)", S, r"(?:to|as)", S,
        r"(?:low|info|informational|none|zero|benign|minimal)\b",
    ),
    _rule(
        "DO-08", "direct_override", 1.5,
        r"\b(?:", _DO_NOT, r"|no\W{1,3}need\W{1,3}to)", S,
        r"(?:escalate|alert|report|flag|notify|raise|investigate)\b",
    ),
    _rule(
        "DO-09", "direct_override", 2.0,
        r"\b(?:system|developer|admin(?:istrator)?)\W{1,3}",
        r"(?:message|prompt|instruction|override|note)\W{0,3}:",
    ),
    # --- role play ---
    _rule(
        "RP-01", "role_play", 3.0,
        r"\byou\W{1,3}are\W{1,3}(?:now\W{1,3})?(?:no\W{1,3}longer\W{1,3}(?:bound|restricted",
        r"|an?\W{1,3}(?:assistant|ai|analyst))|(?:an?|the)\W{1,3}(?:unrestricted|unfiltered",
        r"|uncensored|jailbroken|evil|rogue|different|new)\W{1,3}",
        r"(?:ai|assistant|model|bot|analyst|persona))",
    ),
    _rule(
        "RP-02", "role_play", 2.0,
        r"(?-i:\bDAN\b)|\b(?:do\W{1,3}anything\W{1,3}now|developer\W{1,3}mode",
        r"|jailbreak(?:en|ed)?|god\W{1,3}mode|unrestricted\W{1,3}mode)\b",
    ),
    _rule(
        "RP-03", "role_play", 4.0,
        r"\b(?:you\W{1,3}(?:will|must|should|shall)|please|now|i\W{1,3}want\W{1,3}you\W{1,3}to)",
        S, r"(?:act|behave|pretend|roleplay|respond)\W{1,3}(?:as|like)", S,
        r"(?:(?:an?|the)", S, r")?(?:\w{1,15}", S, r"){0,2}?",
        r"(?:ai|assistant|model|chatbot|persona|character|hacker|attacker|admin|root",
        r"|unrestricted|unfiltered)\b",
    ),
    _rule("RP-04", "role_play", 3.0, r"\bpretend\W{1,4}(?:that\W{1,4})?(?:you|to\W{1,3}be)\b"),
    _rule(
        "RP-05", "role_play", 2.0,
        r"\b(?:imagine|suppose)\W{1,4}you\W{1,3}(?:are|were)\W{1,4}(?:an?|the)\b",
    ),
    _rule(
        "RP-06", "role_play", 1.5,
        r"\b(?:without|no|free\W{1,3}of|beyond)\W{1,3}(?:any\W{1,3})?(?:restrictions?",
        r"|limitations?|filters?|guardrails?|censorship)\b",
    ),
    # --- delimiter escape ---
    _rule(
        "DE-01", "delimiter_escape", 3.0,
        r"\b(?:end|begin|start|close)\W{1,3}(?:of\W{1,3})?(?:untrusted|alert|user|input|data",
        r"|system|trusted)\W{1,3}(?:data|input|block|content|prompt|section|message|alert)\b",
    ),
    _rule("DE-02", "delimiter_escape", 6.0, r"\baisa\W{0,3}untrusted"),
    _rule(
        "DE-03", "delimiter_escape", 6.0,
        r"<\|(?:im_start|im_end|endoftext|eot_id|start_header_id|end_header_id|system",
        r"|assistant|user)\|>|\[/?INST\]|<<\W?/?SYS>>",
    ),
    _rule(
        "DE-04", "delimiter_escape", 4.0,
        r"\b(?:system|assistant)\W{0,2}:\W{1,3}(?:you\W|ignore|disregard|new\W|from\W{1,3}now",
        r"|always|never|do\W{1,3}not)",
    ),
    _rule(
        "DE-05", "delimiter_escape", 3.0,
        r"</?(?:untrusted(?:_data)?|alert_data|system|instructions?|prompt|context)\W{0,2}>",
    ),
    # --- encoded payload (the sanitize-report rules EP-01 and EP-03 are added separately) ---
    _rule(
        "EP-02", "encoded_payload", 4.0,
        r"\bdecode\W{1,4}(?:and\W{1,4})?(?:then\W{1,4})?(?:follow|obey|execute|run|apply)\b",
        r"|\b(?:follow|obey|execute|run)", S, r"(?:the", S, r")?(?:decoded|decrypted)", S,
        r"(?:instructions?|text|content|payload|message|string)",
        r"|\bthe\W{1,4}following\W{1,4}(?:is\W{1,4})?(?:an?\W{1,4})?",
        r"(?:base64|hex|rot13|encoded|encrypted)", S, r"(?:instructions?|string|message|text)",
    ),
    _rule(
        "EP-04", "encoded_payload", 1.0,
        r"(?:%[0-9a-f]{2}){12,60}|(?:\\u[0-9a-f]{4}){6,60}|(?:&#x?[0-9a-f]{2,6};){8,60}",
    ),
    # --- output-format hijack ---
    _rule(
        "OF-01", "output_format_hijack", 3.0,
        r"\b(?:respond|reply|answer|output|return|write|print)", S,
        r"(?:(?:only|just|exactly)", S, r")?(?:with|in|as)", S, r"(?:(?:an?|the)", S, r")?",
        r"(?:plain\W{1,4}text|markdown|html|yaml|xml|csv|free\W{1,3}form|natural\W{1,3}language",
        r"|prose|a\W{1,4}sentence)\b",
    ),
    _rule(
        "OF-02", "output_format_hijack", 2.0,
        r"\b(?:add|include|append|insert|prepend)", S,
        r"(?:(?:an?|the|these|extra|additional)", S, r"){0,2}(?:\w{1,12}", S, r"){0,1}",
        r"(?:keys?|fields?|propert(?:y|ies)|entr(?:y|ies))\b",
    ),
    _rule(
        "OF-03", "output_format_hijack", 4.0,
        r"\b(?:", _DO_NOT, r"|stop)", S, r"(?:output|respond|reply|answer|return|use)", S,
        r"(?:(?:in|with)", S, r")?(?:json|the", S, r"schema|valid", S, r"json)",
    ),
    _rule(
        "OF-04", "output_format_hijack", 4.0,
        r"\bignore", S, r"(?:(?:the|any|all|your)", S, r"){0,2}",
        r"(?:json|schema|output|format|formatting)\b",
    ),
    _rule(
        "OF-05", "output_format_hijack", 3.0,
        r"\b(?:recommended_actions|mitre_technique)\b\W{0,3}[:=]",
    ),
    _rule(
        "OF-06", "output_format_hijack", 2.0,
        r"\b(?:begin|start)", S, r"(?:your", S, r")?(?:response|reply|answer|output)", S, r"with\b",
    ),
    # --- IOC / hallucination bait ---
    _rule(
        "IB-01", "ioc_bait", 4.0,
        r"\b(?:add|include|list|report|mention|recommend|insert|append)", S,
        r"(?:(?:the|these|this|following|an?|new|extra)", S, r"){0,3}",
        r"(?:ips?|ip\W{1,3}addresses|ip\W{1,3}address|domains?|urls?|hashes|hash|iocs?",
        r"|indicators?)", S, _FILL6, r"(?:in|to|as|into)", S, r"(?:(?:your|the)", S, r"){0,2}",
        r"(?:output|response|report|summary|answer|findings?|recommendations?)\b",
    ),
    _rule(
        "IB-02", "ioc_bait", 4.0,
        r"\b(?:you\W{1,3}(?:must|should)|need\W{1,3}to|please)", S,
        r"(?:recommend|advise|tell|instruct)", S, r"(?:the", S, r")?(?:analyst|user|team|soc)?",
        r"\W{0,4}(?:to", S, r")?(?:block|blocklist|blacklist|isolate|disable|delete|wipe|reset",
        r"|shut\W{1,3}down|disconnect)\b",
    ),
    _rule(
        "IB-03", "ioc_bait", 2.0,
        r"\b(?:recommend|suggest|advise)", S,
        r"(?:blocking|blacklisting|isolating|disabling|deleting|wiping|resetting)", S, _FILL,
        r"(?:ip|address|domain|host|account|subnet|range|server|network)\b",
    ),
    _rule(
        "IB-04", "ioc_bait", 3.0,
        r"\b(?:report|state|claim|say|write|conclude)", S, r"(?:that", S, r")?",
        r"(?:this|the\W{1,4}(?:alert|attack|activity)|it)", S, r"(?:is|was|came|originated)", S,
        r"(?:from|by|caused\W{1,3}by|part\W{1,3}of)", S,
        r"(?:apt\W{0,2}\d{1,3}|\w{1,15}\W{1,3}group|nation\W{1,3}state|\w{1,15}\W{1,3}ransomware)",
    ),
    _rule(
        "IB-05", "ioc_bait", 2.0,
        r"\b(?:the|this)", S, r"(?:ip|domain|host|address)", S, r"(?:is|are)", S,
        r"(?:trusted|safe|whitelisted|allow-?listed|approved|authorized)\b",
    ),
    _rule(
        "IB-06", "ioc_bait", 3.0,
        r"\b(?:whitelist|allowlist|trust)", S, r"(?:this|the|these)", S,
        r"(?:ip|domain|host|address|user)",
    ),
    # --- system-prompt exfiltration ---
    _rule(
        "PX-01", "prompt_exfiltration", 6.0,
        r"\b", _VERBS_REVEAL, S, r"(?:me", S, r")?(?:(?:your|the|all|of|its|full|entire",
        r"|complete|exact)", S, r"){0,4}(?:system", S, r"(?:prompt|message|instructions?)",
        r"|(?:hidden|secret|initial|original)", S, r"(?:prompt|instructions?)",
        r"|canary(?:", S, r"(?:token|string|value))?)",
    ),
    _rule(
        "PX-02", "prompt_exfiltration", 5.0,
        r"\b", _VERBS_REVEAL, S, r"(?:me", S, r")?your", S,
        r"(?:(?:system|initial|original|hidden)", S, r")?",
        r"(?:prompt|instructions?|rules|guidelines|configuration)\b",
    ),
    _rule(
        "PX-03", "prompt_exfiltration", 4.0,
        r"\bwhat", S, r"(?:is|are|were|was)", S, r"your", S,
        r"(?:(?:system|initial|original|hidden)", S, r")?",
        r"(?:prompt|instructions?|rules|guidelines|configuration)",
    ),
    _rule("PX-04", "prompt_exfiltration", 3.0, r"!\[[^\]]{0,40}\]\(\W{0,2}https?:"),
    # --- non-English: Russian, Uzbek (Latin and Cyrillic), a few other languages ---
    _rule(
        "NE-01", "non_english", 6.0,
        r"(?:игнорир\w{2,6}|забуд\w{1,6}|отмен\w{2,6}|не\W{1,3}следуй\w{0,3}",
        r"|не\W{1,3}выполня\w{2,6})", S,
        r"(?:(?:все|всё|любые|свои|твои|ваши|эти|данные|мои)", S, r"){0,3}",
        r"(?:(?:предыдущ\w{2,6}|прошл\w{2,6}|прежн\w{2,6}|предшествующ\w{2,6}|системн\w{2,6})",
        S, r"(?:\w{1,12}", S, r"){0,2}?",
        r"(?:инструкци\w{1,4}|указани\w{1,4}|команд\w{1,3}|правил\w{1,3}|промпт\w{0,3}",
        r"|директив\w{1,3})",
        r"|(?:инструкци\w{1,4}|указани\w{1,4}|команд\w{1,3}|правил\w{1,3}|промпт\w{0,3})", S,
        r"(?:выше|ранее|предыдущ\w{2,6}))",
    ),
    _rule(
        "NE-02", "non_english", 4.0,
        r"(?:ты|вы)\W{1,3}(?:теперь|отныне|больше\W{1,3}не)", S, _FILL,
        r"(?:ассистент\w{0,3}|ии|бот\w{0,2}|аналитик\w{0,3}|модель|помощник\w{0,3}",
        r"|ограничени\w{1,3}|свободн\w{1,3})",
        r"|(?:притворись|представь,?\W{1,3}что\W{1,3}ты|действуй\W{1,3}как",
        r"|веди\W{1,3}себя\W{1,3}как)",
    ),
    _rule(
        "NE-03", "non_english", 5.0,
        r"(?:покажи\w{0,3}|выведи\w{0,3}|раскрой\w{0,3}|напечатай\w{0,3}|повтори\w{0,3}",
        r"|расскажи\w{0,3}|назови\w{0,3})", S, r"(?:мне", S, r")?",
        r"(?:(?:свой|свои|твой|твои|весь|полный|скрыт\w{1,3}|секретн\w{1,3}|исходн\w{1,3}",
        r"|начальн\w{1,3}|системн\w{1,3})", S, r"){1,3}",
        r"(?:промпт\w{0,3}|инструкци\w{1,4}|сообщени\w{1,3}|настройк\w{1,3})",
    ),
    _rule(
        "NE-04", "non_english", 6.0,
        r"(?:oldingi|avvalgi|yuqoridagi|barcha|hamma)\W{1,3}(?:\w{1,12}\W{1,3}){0,2}?",
        r"(?:ko", _AP, r"rsatma\w{0,8}|buyruq\w{0,8}|qoida\w{0,8}|yo", _AP, r"riqnoma\w{0,8}",
        r"|prompt\w{0,6})\W{1,3}(?:\w{1,12}\W{1,3}){0,2}?",
        r"(?:e", _AP, r"tiborsiz|unut\w{0,5}|bekor|rad\W{1,3}et|amal\W{1,3}qilma\w{0,5})",
    ),
    _rule(
        "NE-05", "non_english", 6.0,
        r"(?:олдинги|авваль\w{0,3}|юқоридаги|барча|ҳамма)\W{1,3}(?:\w{1,12}\W{1,3}){0,2}?",
        r"(?:к[ўу]рсатма\w{0,8}|буйруқ\w{0,8}|қоида\w{0,8}|й[ўу]риқнома\w{0,8}|промпт\w{0,6}",
        r"|инструкци\w{1,4})\W{1,3}(?:\w{1,12}\W{1,3}){0,2}?",
        r"(?:эътиборсиз|унут\w{0,5}|бекор|рад\W{1,3}эт|амал\W{1,3}қилма\w{0,5})",
    ),
    _rule(
        "NE-06", "non_english", 5.0,
        r"(?:tizim|тизим)\W{1,3}(?:prompt|промпт|so", _AP, r"rovi|ko", _AP, r"rsatma",
        r"|к[ўу]рсатма)\w{0,6}\W{1,3}(?:\w{1,10}\W{1,3}){0,2}?",
        r"(?:ko", _AP, r"rsat|chiqar|ayt|yoz|ber|к[ўу]рсат|чиқар|айт|ёз|бер)\w{0,5}",
        r"|\bsen\W{1,3}endi\W{1,4}(?:\w{1,15}\W{1,4}){0,2}?",
        r"(?:yordamchi\w{0,5}|bot\w{0,3}|assistent\w{0,4}|cheklov\w{0,8}|erkin\w{0,4})",
    ),
    _rule(
        "NE-07", "non_english", 6.0,
        r"\bignora\w{0,2}\W{1,3}(?:(?:todas|todo|las|tus|mis|estas)\W{1,3}){0,3}",
        r"(?:instrucciones|indicaciones|reglas)\W{1,3}(?:anteriores|previas|de\W{1,3}arriba)",
        r"|\bignore[zr]?\W{1,3}(?:(?:toutes|tout|les|vos|tes|ces)\W{1,3}){0,3}",
        r"(?:instructions|consignes|r\u00e8gles)\W{1,3}",
        r"(?:pr\u00e9c\u00e9dentes|ant\u00e9rieures|ci-dessus)",
        r"|\bignorier\w{1,3}\W{1,3}(?:(?:alle|die|deine|ihre|diese)\W{1,3}){0,3}",
        r"(?:vorherigen|fr\u00fcheren|obigen|bisherigen)\W{1,3}",
        r"(?:anweisungen|instruktionen|regeln|befehle)",
        r"|\u5ffd\u7565(?:\u4e4b\u524d|\u4ee5\u4e0a|\u4e0a\u8ff0|\u5148\u524d|\u6240\u6709)",
        r"\u7684?(?:\u6240\u6709)?(?:\u6307\u4ee4|\u6307\u793a|\u63d0\u793a|\u89c4\u5219|\u8bf4\u660e)",
    ),
)
# fmt: on

# Rules driven by the sanitizer's report rather than by a pattern. Same id scheme and weights.
REPORT_RULES: Final = {
    "EP-01": ("encoded_payload", 2.0),  # a base64/hex/escape blob in a field
    "EP-03": ("encoded_payload", 2.0),  # a word mixing Latin with Cyrillic or Greek
}

ALL_RULE_IDS: Final = tuple(rule.id for rule in RULES) + tuple(REPORT_RULES)


@dataclass(frozen=True)
class RuleMatch:
    """One fired rule: id, category, weight and the field names it matched (never the text)."""

    rule_id: str
    category: str
    weight: float
    fields: tuple[str, ...]


@dataclass(frozen=True)
class DetectionResult:
    category_scores: dict[str, float]
    total: float
    matches: tuple[RuleMatch, ...]
    decision: Decision
    thresholds: Thresholds

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "total": self.total,
            "thresholds": {"flag": self.thresholds.flag, "block": self.thresholds.block},
            "category_scores": self.category_scores,
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "category": m.category,
                    "weight": m.weight,
                    "fields": list(m.fields),
                }
                for m in self.matches
            ],
        }


def detect_fields(
    fields: Mapping[str, str | None],
    report: SanitizeReport | None = None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> DetectionResult:
    """Score already-sanitized field values, plus the sanitizer's report when given."""
    hits: dict[str, list[str]] = {}
    for name, value in fields.items():
        if not value:
            continue
        text = value[:MAX_SCAN_CHARS]
        skeleton = homoglyph_skeleton(text)
        variants = (text,) if skeleton == text else (text, skeleton)
        for rule in RULES:
            if any(rule.pattern.search(variant) for variant in variants):
                hits.setdefault(rule.id, []).append(name)
    if report is not None:
        for name, field_report in report.fields.items():
            if field_report.encoded_blobs:
                hits.setdefault("EP-01", []).append(name)
            if field_report.mixed_script_tokens:
                hits.setdefault("EP-03", []).append(name)

    by_id = {rule.id: rule for rule in RULES}
    matches = tuple(
        RuleMatch(
            rule_id,
            *(
                (by_id[rule_id].category, by_id[rule_id].weight)
                if rule_id in by_id
                else REPORT_RULES[rule_id]
            ),
            fields=tuple(names),
        )
        for rule_id, names in sorted(hits.items())
    )
    scores = dict.fromkeys(CATEGORIES, 0.0)
    for match in matches:
        scores[match.category] += match.weight
    scores = {name: min(score, CATEGORY_CAP) for name, score in scores.items()}
    total = sum(scores.values())
    decision: Decision = (
        "block" if total >= thresholds.block else "flag" if total >= thresholds.flag else "pass"
    )
    return DetectionResult(scores, total, matches, decision, thresholds)


def detect(
    alert: SanitizedAlert,
    report: SanitizeReport | None = None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> DetectionResult:
    """Score a sanitized alert (D10)."""
    return detect_fields(alert.fields, report, thresholds)
