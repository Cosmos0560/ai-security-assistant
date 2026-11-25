"""The eval runner: the dataset through the pipeline in every D22 configuration.

* The NAIVE mock runs under each of the four ``DefenseConfig`` values. It obeys injected
  instructions, so its accepted outputs show what each configuration lets through.
* The WELL-BEHAVED mock runs under ``all`` only: on the benign alerts that gives the operational
  cost of the defenses (benign alerts sent to human review).

Every run uses the same seed, so the canary and the nonce are the same in every configuration and
the whole eval is deterministic. No network, no real provider: the eval is mock-only by design.

``run_live`` is the one exception, and no test, gate or CI run gives it a real provider: the owner
runs it by hand (``aisa eval --provider ollama|anthropic``, docs/LIVE_EVAL.md). One real provider
answers in every selected configuration, and its ``all`` run doubles as the operational run. It is
resumable (D44): every (sample, configuration) pair is written to a checkpoint as soon as it is
done. Its numbers go to a separate file and never into the README table.

With ``reuse``, each distinct prompt (system and user together) is sent once, and every other pair
with the same prompt takes that result: the reply, or the error. The configurations that sanitize
build the same prompt, so they then judge ONE reply, and what differs between them is the defenses
alone. Each configuration still runs its own detector and validator. A context refusal sends
nothing, so there is nothing to reuse.

Slicing never changes the facts: the D41 batch patterns are computed from the FULL dataset first,
and ``--subset``, ``--limit`` and ``--configs`` only choose which alerts are sent to the model.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, TypeVar

from ai_security_assistant.detector.canary import new_canary
from ai_security_assistant.eval.checkpoint import (
    KIND_MALFORMED,
    KIND_NOT_CALLED,
    KIND_PROVIDER_ERROR,
    KIND_REFUSED,
    KIND_REPLY,
    REQUEST_KINDS,
    Checkpoint,
    CheckpointError,
    Key,
    Record,
)
from ai_security_assistant.eval.dataset import LABELS, Sample, WindowsSample
from ai_security_assistant.kb import PatternFact
from ai_security_assistant.kb.patterns import batch_patterns
from ai_security_assistant.pipeline import (
    AlertOutcome,
    DefenseConfig,
    run_alert,
    run_pipeline,
    system_prompt_for,
)
from ai_security_assistant.providers.base import (
    BudgetExhausted,
    CallBudget,
    ContextBudgetExceeded,
    MalformedReply,
    Provider,
    ProviderError,
)
from ai_security_assistant.providers.mock import NaiveMock, WellBehavedMock
from ai_security_assistant.wrap import new_nonce

SEED: Final = "aisa-eval-1"
SUBSETS: Final = ("all", "dev", "heldout")
STOPPED_BUDGET: Final = "budget"
STOPPED_INTERRUPTED: Final = "interrupted"


@dataclass(frozen=True)
class ConfigRun:
    """One configuration's outcomes with the canary that run used. ``samples`` are the alerts the
    outcomes belong to, in the same order: every alert in a mock run, the finished ones live."""

    config: DefenseConfig
    provider: str
    prompt_version: str
    canary: str
    outcomes: tuple[AlertOutcome, ...]
    samples: tuple[Sample, ...]


@dataclass(frozen=True)
class EvalRun:
    seed: str
    samples: tuple[Sample, ...]  # the alerts the run was asked to do
    naive: tuple[ConfigRun, ...]  # one per configuration run, in DefenseConfig order
    well_behaved_all: ConfigRun
    batch: tuple[Sample, ...] = ()  # the full dataset, when ``samples`` is a slice of it

    @property
    def full_set(self) -> tuple[Sample, ...]:
        return self.batch or self.samples

    def naive_run(self, config: DefenseConfig) -> ConfigRun:
        """The run of ``config``, or an empty one if it was not selected (a live slice)."""
        for run in self.naive:
            if run.config is config:
                return run
        return _empty_run(config, self.naive[0].provider, self.seed)


def _empty_run(config: DefenseConfig, provider: str, seed: str) -> ConfigRun:
    _system, version = system_prompt_for(config, new_canary(seed))
    return ConfigRun(config, provider, version, new_canary(seed), (), ())


def run_config(
    samples: Sequence[Sample], config: DefenseConfig, *, naive: bool, seed: str
) -> ConfigRun:
    budget = CallBudget(len(samples))
    provider = NaiveMock(budget) if naive else WellBehavedMock(budget)
    result = run_pipeline(
        [sample.alert for sample in samples], provider, budget, config=config, seed=seed
    )
    return ConfigRun(
        config=config,
        provider=result.provider,
        prompt_version=result.prompt_version,
        canary=new_canary(seed),
        outcomes=result.outcomes,
        samples=tuple(samples),
    )


def run_eval(samples: Sequence[Sample], seed: str = SEED) -> EvalRun:
    """The full ablation over ``samples``: deterministic for a given ``seed``."""
    return EvalRun(
        seed=seed,
        samples=tuple(samples),
        naive=tuple(run_config(samples, config, naive=True, seed=seed) for config in DefenseConfig),
        well_behaved_all=run_config(samples, DefenseConfig.ALL, naive=False, seed=seed),
    )


# ---------------------------------------------------------------- which alerts a live run does

_T = TypeVar("_T")


def _in_turn(queues: Sequence[Sequence[_T]]) -> list[_T]:
    """One item from each queue in turn until all are empty."""
    longest = max((len(queue) for queue in queues), default=0)
    return [queue[i] for i in range(longest) for queue in queues if i < len(queue)]


def _stratum(sample: Sample) -> str:
    if isinstance(sample, WindowsSample):
        return str(sample.attack_goal) if sample.is_injection else sample.group
    return str(sample.category) if sample.is_injection else str(sample.hard_negative)


def stratified_order(samples: Sequence[Sample]) -> tuple[Sample, ...]:
    """The fixed order of a live run: benign and injection alternate, and within each the strata
    take turns (main: category, or hard negative; Windows: attack goal, or group), each in dataset
    order. So any prefix, a ``--limit`` or a run stopped for the night, is a mix."""
    by_label = []
    for label in LABELS:
        strata: dict[str, list[Sample]] = {}
        for sample in samples:
            if sample.label == label:
                strata.setdefault(_stratum(sample), []).append(sample)
        by_label.append(_in_turn(list(strata.values())))
    return tuple(_in_turn(by_label))


def select_samples(
    samples: Sequence[Sample], *, subset: str = "all", limit: int | None = None
) -> tuple[Sample, ...]:
    """The alerts of ``--subset`` in the fixed order, the first ``--limit`` of them."""
    pool = [sample for sample in samples if subset == "all" or sample.split == subset]
    ordered = stratified_order(pool)
    return ordered if limit is None else ordered[:limit]


# ---------------------------------------------------------------- the resumable live run


def _prompt_hash(system: str, user: str) -> str:
    return hashlib.sha256(f"{system}\x00{user}".encode("utf-8", "surrogatepass")).hexdigest()


def _answer(kind: str, raw_text: str | None, reason: str | None) -> str:
    """Give the pipeline a recorded result again: the text, or the same error."""
    if kind == KIND_REPLY and raw_text is not None:
        return raw_text
    if kind == KIND_MALFORMED and reason is not None:
        raise MalformedReply(reason)
    if kind == KIND_REFUSED:
        raise ContextBudgetExceeded("recorded refusal")
    raise ProviderError("recorded error")


class _Recorder:
    """Wraps the real provider for ONE pair and notes what its call gave and how long it took.

    ``answered`` maps a prompt hash to the record that holds its result (empty without reuse): a
    prompt found there is answered from it, and nothing is sent.
    """

    def __init__(
        self, inner: Provider, clock: Callable[[], float], answered: Mapping[str, Record]
    ) -> None:
        self.name = inner.name
        self._inner = inner
        self._clock = clock
        self._answered = answered
        self.reused = False
        self.kind = KIND_NOT_CALLED
        self.reason: str | None = None
        self.raw_text: str | None = None
        self.prompt_sha256: str | None = None
        self.latency_ms: int | None = None
        self.exhausted = False

    def complete(self, system: str, user: str) -> str:
        self.prompt_sha256 = _prompt_hash(system, user)
        source = self._answered.get(self.prompt_sha256)
        if source is not None:
            self.reused, self.kind = True, source.kind
            return _answer(source.kind, source.raw_text, source.reason)
        start = self._clock()

        def took() -> int:
            return round((self._clock() - start) * 1000)

        try:
            text = self._inner.complete(system, user)
        except BudgetExhausted:
            self.exhausted = True
            raise
        except ContextBudgetExceeded:
            self.kind = KIND_REFUSED  # no request was made, so there is no latency
            raise
        except MalformedReply as exc:
            self.kind, self.reason, self.latency_ms = KIND_MALFORMED, exc.reason, took()
            raise
        except ProviderError:
            self.kind, self.latency_ms = KIND_PROVIDER_ERROR, took()
            raise
        self.kind, self.raw_text, self.latency_ms = KIND_REPLY, text, took()
        return text


class _Replay:
    """Answers with what a checkpoint line recorded, if the prompt is still the same. ``source``
    is the line that holds the text: the record itself unless it is a reuse."""

    name = "replay"

    def __init__(self, record: Record, source: Record) -> None:
        self._record = record
        self._source = source
        self.called = False

    def complete(self, system: str, user: str) -> str:
        self.called = True
        record = self._record
        if record.prompt_sha256 != _prompt_hash(system, user):
            raise CheckpointError(
                f"{record.config} {record.sample_id!a}: the prompt differs from the one recorded "
                "(the code or the data changed since the checkpoint was written)"
            )
        return _answer(record.kind, self._source.raw_text, self._source.reason)


class _Probe:
    """Notes the prompt the pipeline would send for a pair, if any. Never calls anything."""

    name = "probe"

    def __init__(self) -> None:
        self.prompt_sha256: str | None = None

    def complete(self, system: str, user: str) -> str:
        self.prompt_sha256 = _prompt_hash(system, user)
        return ""


@dataclass(frozen=True)
class _Pair:
    sample: Sample
    config: DefenseConfig
    pattern: PatternFact | None  # from the FULL dataset
    seed: str

    @property
    def key(self) -> Key:
        return self.config.label, self.sample.sample_id

    def run(self, provider: Provider) -> AlertOutcome:
        canary = new_canary(self.seed)
        system, _version = system_prompt_for(self.config, canary)
        return run_alert(
            self.sample.alert,
            provider,
            config=self.config,
            system=system,
            canary=canary,
            nonce=new_nonce(self.seed),
            pattern=self.pattern,
        )


def _source(record: Record, originals: Mapping[str, Record]) -> Record:
    """The line that holds the text of ``record``."""
    if not record.reused or record.kind == KIND_PROVIDER_ERROR:  # an error has no text
        return record
    source = originals.get(record.prompt_sha256 or "")
    if source is None or source.kind != record.kind:
        raise CheckpointError(
            f"{record.config} {record.sample_id!a}: no stored original for this reused reply"
        )
    return source


def _replayed(pair: _Pair, record: Record, originals: Mapping[str, Record]) -> AlertOutcome:
    replay = _Replay(record, _source(record, originals))
    outcome = pair.run(replay)
    same = (
        replay.called is (record.kind != KIND_NOT_CALLED)
        and outcome.status.value == record.status
        and outcome.reasons == record.reasons
    )
    if not same:
        raise CheckpointError(
            f"{record.config} {record.sample_id!a}: the pipeline now decides differently from the "
            "checkpoint (the code changed since it was written)"
        )
    return outcome


@dataclass(frozen=True)
class LiveResult:
    """Where a live run stands, whether this invocation finished it or not."""

    run: EvalRun
    records: Mapping[Key, Record]
    outcomes: Mapping[Key, AlertOutcome]
    selected: int  # pairs
    stopped: str | None = None  # STOPPED_BUDGET, STOPPED_INTERRUPTED or None
    reuse: bool = False
    calls_made: int = 0  # requests recorded over all sittings, replaced errors included

    @property
    def pending(self) -> int:
        return self.selected - len(self.records)

    @property
    def errored(self) -> int:
        return sum(1 for r in self.records.values() if r.kind == KIND_PROVIDER_ERROR)

    @property
    def complete(self) -> bool:
        return self.pending == 0 and self.errored == 0

    @property
    def distinct_prompts(self) -> int:
        """The different prompts behind the pairs that reached the model step with a request."""
        return len({r.prompt_sha256 for r in self.records.values() if r.kind in REQUEST_KINDS})

    @property
    def replies_reused(self) -> int:
        """Pairs judged on the reply of an identical prompt, with no request of their own."""
        return sum(
            1 for r in self.records.values() if r.reused and r.kind in (KIND_REPLY, KIND_MALFORMED)
        )

    def latencies(self, config: str | None = None) -> list[int]:
        """Milliseconds of every REAL call that got a reply, over all sittings; of ``config``
        only, if given. A reused reply took no call, so it has no latency."""
        return [
            r.latency_ms
            for r in self.records.values()
            if (config is None or r.config == config)
            and r.kind in (KIND_REPLY, KIND_MALFORMED)
            and r.latency_ms is not None
        ]


def _duration(seconds: float) -> str:
    minutes, secs = divmod(round(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    return f"{minutes}m{secs:02d}s" if minutes else f"{secs}s"


def _eta(waiting: Sequence[str], records: Mapping[Key, Record]) -> str:
    """The time left for the calls in ``waiting`` (one config label each), from the latencies
    measured so far: the configuration's own mean, else the mean of all calls."""
    seen: dict[str, list[int]] = {}
    for record in records.values():
        if record.kind in (KIND_REPLY, KIND_MALFORMED) and record.latency_ms is not None:
            seen.setdefault(record.config, []).append(record.latency_ms)
    every = [value for values in seen.values() for value in values]
    if not waiting:
        return "no model calls left"
    left = f"{len(waiting)} model calls left"
    if not every:
        return f"{left}, ETA unknown until one is measured"
    overall = sum(every) / len(every)
    total = sum(sum(seen[c]) / len(seen[c]) if c in seen else overall for c in waiting)
    return f"{left}, ETA about {_duration(total / 1000)}"


def run_live(
    samples: Sequence[Sample],
    batch: Sequence[Sample],
    configs: Sequence[DefenseConfig],
    provider: Provider,
    checkpoint: Checkpoint,
    *,
    retry_errors: bool = False,
    reuse: bool = False,
    seed: str = SEED,
    clock: Callable[[], float] = time.monotonic,
    progress: Callable[[str], None] = lambda _line: None,
) -> LiveResult:
    """Run what the checkpoint does not hold yet; one sample through every configuration, then
    the next. A pair that ended in a provider error is kept as it is unless ``retry_errors``.

    ``samples`` is the selection and ``batch`` the full dataset. ``reuse`` sends each distinct
    prompt once and must be the same in every sitting of a checkpoint (its header pins it).
    Raises ``CheckpointError`` before any call if a recorded pair does not replay exactly.
    """
    facts = batch_patterns([sample.alert for sample in batch])
    patterns = {sample.sample_id: facts.get(i) for i, sample in enumerate(batch)}
    pairs = [
        _Pair(sample, config, patterns[sample.sample_id], seed)
        for sample in samples
        for config in configs
    ]
    by_key = {pair.key: pair for pair in pairs}
    outcomes: dict[Key, AlertOutcome] = {}
    originals = {
        r.prompt_sha256: r
        for r in checkpoint.records.values()
        if r.prompt_sha256 is not None and not r.reused and r.kind in (KIND_REPLY, KIND_MALFORMED)
    }
    for key, record in checkpoint.records.items():
        if key not in by_key:
            raise CheckpointError("the checkpoint holds a pair that this run did not select")
        outcomes[key] = _replayed(by_key[key], record, originals)

    def waiting(pair: _Pair) -> bool:
        record = checkpoint.records.get(pair.key)
        return record is None or (retry_errors and record.kind == KIND_PROVIDER_ERROR)

    todo = [pair for pair in pairs if waiting(pair)]
    # What a prompt already gave. An error counts too (a prompt is asked once), except one that
    # is about to be retried.
    answered: dict[str, Record] = {}
    if reuse:
        answered.update(originals)
        if not retry_errors:
            for r in checkpoint.records.values():
                if r.prompt_sha256 is not None and r.kind == KIND_PROVIDER_ERROR:
                    answered.setdefault(r.prompt_sha256, r)
    calls = []  # the pairs of ``todo`` that will send a request
    planned = set(answered)
    for pair in todo:
        probe = _Probe()
        pair.run(probe)
        if probe.prompt_sha256 is not None and probe.prompt_sha256 not in planned:
            calls.append(pair.key)
            if reuse:
                planned.add(probe.prompt_sha256)

    def eta() -> str:
        return _eta([config for config, _sample in calls], checkpoint.records)

    errored = sum(1 for r in checkpoint.records.values() if r.kind == KIND_PROVIDER_ERROR)
    kept = f", {errored} of them errored" if errored else ""
    progress(
        f"aisa: {len(samples)} alerts x {len(configs)} configs = {len(pairs)} pairs; "
        f"{len(checkpoint.records)} in the checkpoint{kept}; {len(todo)} to run; {eta()}"
    )

    stopped = None
    for pair in todo:
        recorder = _Recorder(provider, clock, answered)
        try:
            outcome = pair.run(recorder)
            if recorder.exhausted:
                stopped = STOPPED_BUDGET
                break
            record = Record(
                config=pair.config.label,
                sample_id=pair.sample.sample_id,
                kind=recorder.kind,
                reason=recorder.reason,
                reused=recorder.reused,
                status=outcome.status.value,
                reasons=outcome.reasons,
                prompt_sha256=recorder.prompt_sha256,
                latency_ms=recorder.latency_ms,
                raw_text=recorder.raw_text,
            )
            checkpoint.append(record)
            outcomes[pair.key] = outcome
            if reuse and record.requested and record.prompt_sha256 is not None:
                answered[record.prompt_sha256] = record
            if pair.key in calls:
                calls.remove(pair.key)
            took = "" if record.latency_ms is None else f" in {_duration(record.latency_ms / 1000)}"
            if record.reused:
                took = " (reused)"
            progress(
                f"aisa: [{len(checkpoint.records)}/{len(pairs)}] {record.config} "
                f"{record.sample_id}: {record.eval_status}{took}; {eta()}"
            )
        except KeyboardInterrupt:
            stopped = STOPPED_INTERRUPTED
            break

    records = {key: record for key, record in checkpoint.records.items() if key in outcomes}
    runs = []
    for config in configs:
        done = [
            sample
            for sample in samples
            if (config.label, sample.sample_id) in records
            and records[config.label, sample.sample_id].kind != KIND_PROVIDER_ERROR
        ]
        _system, version = system_prompt_for(config, new_canary(seed))
        runs.append(
            ConfigRun(
                config=config,
                provider=provider.name,
                prompt_version=version,
                canary=new_canary(seed),
                outcomes=tuple(outcomes[config.label, s.sample_id] for s in done),
                samples=tuple(done),
            )
        )
    operational = next(
        (r for r in runs if r.config is DefenseConfig.ALL),
        _empty_run(DefenseConfig.ALL, provider.name, seed),
    )
    run = EvalRun(seed, tuple(samples), tuple(runs), operational, batch=tuple(batch))
    return LiveResult(run, records, outcomes, len(pairs), stopped, reuse, checkpoint.calls_made)
