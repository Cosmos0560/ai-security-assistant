"""The fixed pipeline (D5) with the four D22 defense configurations.

Stages, per alert: ingest (done by the caller) -> sanitize + wrap -> detector -> provider ->
validator -> outcome. Every alert ends in exactly one status:

* ``triaged``             a verdict was accepted;
* ``needs_human_review``  the detector blocked it (D10), or the validator rejected the reply
                          (D12), or there was no reply to read;
* ``budget_exhausted``    the run's call budget was spent before this alert (T8).

``DefenseConfig`` has exactly the four configurations of D22 and nothing else:

==================  ===============  ========  =========
config              sanitize + wrap  detector  validator
==================  ===============  ========  =========
``none``            off              off       off
``detector-only``   on               on        off
``validator-only``  on               off       on
``all``             on               on        on
==================  ===============  ========  =========

With the validator OFF the reply is read PERMISSIVELY (``validator.read_permissive``): a JSON
object is accepted with its fields as they are (any severity string, any action string), and
anything else is accepted as prose. That models an undefended system honestly for the ablation;
the strict schema check belongs to the validator layer only. With sanitize + wrap OFF (``none``)
the run uses the NAIVE prompt pair (D35): a system prompt with no trust rules and a user prompt
of raw, unsanitized ``name: value`` lines with no boundary. The canary is in the system prompt in
every configuration, because it is measurement instrumentation, not a defense.

The configurations are reachable only through this Python API (the Phase 6 eval). ``aisa
triage`` always runs ``all`` and has no option to weaken it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Final

from ai_security_assistant.detector.canary import new_canary
from ai_security_assistant.detector.heuristics import DetectionResult, detect
from ai_security_assistant.kb import PatternFact, ReferenceFacts, reference_facts
from ai_security_assistant.kb.patterns import batch_patterns
from ai_security_assistant.models import Alert
from ai_security_assistant.prompt import (
    NAIVE_PROMPT_VERSION,
    PROMPT_VERSION,
    build_naive_system_prompt,
    build_plain_user_prompt,
    build_system_prompt,
    build_user_prompt,
)
from ai_security_assistant.providers.base import CallBudget, Provider
from ai_security_assistant.sanitize import sanitize_alert
from ai_security_assistant.schema import TriageOutput
from ai_security_assistant.triage import TriageResult, TriageStatus, triage_alert
from ai_security_assistant.validator import read_permissive, validate
from ai_security_assistant.validator.severity import severity_floor
from ai_security_assistant.wrap import new_nonce

REASON_DETECTOR_BLOCK: Final = "detector.block"
REASON_BUDGET_EXHAUSTED: Final = "provider.budget_exhausted"


class Status(StrEnum):
    TRIAGED = "triaged"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    BUDGET_EXHAUSTED = "budget_exhausted"


class DefenseConfig(Enum):
    """The four D22 configurations: ``(name, sanitize + wrap, detector, validator)``."""

    NONE = ("none", False, False, False)
    DETECTOR_ONLY = ("detector-only", True, True, False)
    VALIDATOR_ONLY = ("validator-only", True, False, True)
    ALL = ("all", True, True, True)

    label: str
    sanitize_wrap: bool
    detector: bool
    validator: bool

    def __init__(self, label: str, sanitize_wrap: bool, detector: bool, validator: bool) -> None:
        self.label = label
        self.sanitize_wrap = sanitize_wrap
        self.detector = detector
        self.validator = validator

    @classmethod
    def from_label(cls, label: str) -> DefenseConfig:
        for config in cls:
            if config.label == label:
                return config
        raise ValueError("unknown defense config")


@dataclass(frozen=True)
class DetectorSummary:
    """The detector's decision, score and fired rule ids (never the matched text)."""

    decision: str
    total: float
    rule_ids: tuple[str, ...]
    categories: tuple[str, ...]

    @classmethod
    def from_result(cls, result: DetectionResult) -> DetectorSummary:
        return cls(
            decision=result.decision,
            total=result.total,
            rule_ids=tuple(match.rule_id for match in result.matches),
            categories=tuple(name for name, score in result.category_scores.items() if score > 0),
        )


@dataclass(frozen=True)
class AcceptedVerdict:
    """What a run accepted for one alert.

    ``validated`` is True when the validator accepted it: the fields are then the strict
    ``TriageOutput`` values. Otherwise (validator OFF) they are whatever the model wrote; ``prose``
    marks a reply that was not a JSON object, whose text is then the summary.
    """

    severity: str | None
    mitre_technique: str | None
    summary: str | None
    recommended_actions: tuple[str, ...]
    confidence: float | None
    validated: bool
    prose: bool = False

    @classmethod
    def from_output(cls, output: TriageOutput) -> AcceptedVerdict:
        return cls(
            severity=output.severity.value,
            mitre_technique=output.mitre_technique,
            summary=output.summary,
            recommended_actions=tuple(action.value for action in output.recommended_actions),
            confidence=output.confidence,
            validated=True,
        )

    @classmethod
    def permissive(cls, raw_text: str) -> AcceptedVerdict:
        view = read_permissive(raw_text)
        if view.fields is None:
            return cls(
                severity=None,
                mitre_technique=None,
                summary=raw_text,
                recommended_actions=(),
                confidence=None,
                validated=False,
                prose=True,
            )
        return cls(
            severity=view.severity,
            mitre_technique=view.mitre_technique,
            summary=view.summary,
            recommended_actions=view.recommended_actions or (),
            confidence=view.confidence,
            validated=False,
        )


@dataclass(frozen=True)
class AlertOutcome:
    """The result for one alert. ``verdict`` is set exactly when ``status`` is ``triaged``."""

    alert: Alert
    status: Status
    verdict: AcceptedVerdict | None
    reasons: tuple[str, ...]
    detector: DetectorSummary | None  # None when the detector is off
    called_provider: bool
    # The provider's reply as it came (None if there was none). Untrusted; only report.json with
    # --include-raw shows it, never report.md, and repr never does.
    raw_text: str | None = field(default=None, repr=False)
    # Trusted Windows reference facts for this alert (D40); None when the config is ``none`` or no
    # table key matched. Table text and counted integers only, never alert text.
    facts: ReferenceFacts | None = None

    @property
    def severity_floor(self) -> str | None:
        floor = severity_floor(self.alert.source, self.alert.severity_raw)
        return None if floor is None else floor.value


@dataclass(frozen=True)
class RunResult:
    config: DefenseConfig
    provider: str
    prompt_version: str
    outcomes: tuple[AlertOutcome, ...]
    calls_used: int
    calls_max: int

    def counts(self) -> dict[str, int]:
        """Alerts per status, every status present, in ``Status`` order."""
        counts = dict.fromkeys((status.value for status in Status), 0)
        for outcome in self.outcomes:
            counts[outcome.status.value] += 1
        return counts

    @property
    def all_triaged(self) -> bool:
        return all(outcome.status is Status.TRIAGED for outcome in self.outcomes)


def plain_prompt(alert: Alert) -> str:
    """The user prompt with sanitize + wrap OFF (config ``none``): raw values, no boundary."""
    return build_plain_user_prompt(alert)


def system_prompt_for(config: DefenseConfig, canary: str) -> tuple[str, str]:
    """``(system prompt, prompt version)`` for ``config``: the naive pair for ``none`` (D35)."""
    if config.sanitize_wrap:
        return build_system_prompt(canary), PROMPT_VERSION
    return build_naive_system_prompt(canary), NAIVE_PROMPT_VERSION


def _decide(
    alert: Alert,
    result: TriageResult,
    config: DefenseConfig,
    canary: str,
    pattern: PatternFact | None = None,
) -> tuple[Status, AcceptedVerdict | None, tuple[str, ...]]:
    if result.status is TriageStatus.BUDGET_EXHAUSTED:
        return Status.BUDGET_EXHAUSTED, None, (REASON_BUDGET_EXHAUSTED,)
    if config.validator:
        checked = validate(result, alert, canary, pattern)
        if checked.output is None:
            return Status.NEEDS_HUMAN_REVIEW, None, checked.reasons
        return Status.TRIAGED, AcceptedVerdict.from_output(checked.output), ()
    if result.raw_text is None:  # nothing to read, even permissively
        return Status.NEEDS_HUMAN_REVIEW, None, (f"provider.{result.status.value}",)
    return Status.TRIAGED, AcceptedVerdict.permissive(result.raw_text), ()


def run_alert(
    alert: Alert,
    provider: Provider,
    *,
    config: DefenseConfig,
    system: str,
    canary: str,
    nonce: str,
    pattern: PatternFact | None = None,
) -> AlertOutcome:
    """One alert through the stages ``config`` switches on. Never raises for a bad reply.

    ``pattern`` is the alert's batch fact (D41). Reference facts are input preparation (D22): on
    in every configuration except ``none``. The validator also gets ``pattern`` (check 9, D42).
    """
    detector: DetectorSummary | None = None
    facts: ReferenceFacts | None = None
    if config.sanitize_wrap:
        facts = reference_facts(alert, pattern)
        sanitized, report = sanitize_alert(alert)
        user = build_user_prompt(sanitized, nonce, facts)
        if config.detector:
            detection = detect(sanitized, report)
            detector = DetectorSummary.from_result(detection)
            if detection.decision == "block":  # D10: a blocked alert never reaches the model
                return AlertOutcome(
                    alert=alert,
                    status=Status.NEEDS_HUMAN_REVIEW,
                    verdict=None,
                    reasons=(REASON_DETECTOR_BLOCK,),
                    detector=detector,
                    called_provider=False,
                    facts=facts,
                )
    else:
        user = plain_prompt(alert)
    result = triage_alert(provider, system, user)
    status, verdict, reasons = _decide(alert, result, config, canary, pattern)
    return AlertOutcome(
        alert=alert,
        status=status,
        verdict=verdict,
        reasons=reasons,
        detector=detector,
        called_provider=result.status is not TriageStatus.BUDGET_EXHAUSTED,
        raw_text=result.raw_text,
        facts=facts,
    )


def run_pipeline(
    alerts: Iterable[Alert],
    provider: Provider,
    budget: CallBudget,
    *,
    config: DefenseConfig = DefenseConfig.ALL,
    seed: int | str | None = None,
) -> RunResult:
    """Run every alert under one canary and one nonce. ``seed`` makes both deterministic."""
    if not isinstance(config, DefenseConfig):
        raise TypeError("config must be a DefenseConfig")
    canary = new_canary(seed)
    nonce = new_nonce(seed)
    system, prompt_version = system_prompt_for(config, canary)
    batch = list(alerts)
    # D41: the pattern of a source address needs the whole batch, so it is computed before the loop.
    # Both the reference block and validator check 9 (D42) use it.
    patterns = batch_patterns(batch) if config.sanitize_wrap or config.validator else {}
    outcomes: Sequence[AlertOutcome] = [
        run_alert(
            alert,
            provider,
            config=config,
            system=system,
            canary=canary,
            nonce=nonce,
            pattern=patterns.get(index),
        )
        for index, alert in enumerate(batch)
    ]
    return RunResult(
        config=config,
        provider=provider.name,
        prompt_version=prompt_version,
        outcomes=tuple(outcomes),
        calls_used=budget.used,
        calls_max=budget.max_calls,
    )
