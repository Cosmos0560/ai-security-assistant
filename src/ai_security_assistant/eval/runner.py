"""The eval runner: the dataset through the pipeline in every D22 configuration.

* The NAIVE mock runs under each of the four ``DefenseConfig`` values. It obeys injected
  instructions, so its accepted outputs show what each configuration lets through.
* The WELL-BEHAVED mock runs under ``all`` only: on the benign alerts that gives the operational
  cost of the defenses (benign alerts sent to human review).

Every run uses the same seed, so the canary and the nonce are the same in every configuration and
the whole eval is deterministic. No network, no real provider: the eval is mock-only by design.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from ai_security_assistant.detector.canary import new_canary
from ai_security_assistant.eval.dataset import Sample
from ai_security_assistant.pipeline import AlertOutcome, DefenseConfig, run_pipeline
from ai_security_assistant.providers.base import CallBudget
from ai_security_assistant.providers.mock import NaiveMock, WellBehavedMock

SEED: Final = "aisa-eval-1"


@dataclass(frozen=True)
class ConfigRun:
    """One configuration's outcomes, in dataset order, with the canary that run used."""

    config: DefenseConfig
    provider: str
    prompt_version: str
    canary: str
    outcomes: tuple[AlertOutcome, ...]


@dataclass(frozen=True)
class EvalRun:
    seed: str
    samples: tuple[Sample, ...]
    naive: tuple[ConfigRun, ...]  # one per DefenseConfig, in DefenseConfig order
    well_behaved_all: ConfigRun

    def naive_run(self, config: DefenseConfig) -> ConfigRun:
        return next(run for run in self.naive if run.config is config)


def run_config(
    samples: Sequence[Sample], config: DefenseConfig, *, naive: bool, seed: str
) -> ConfigRun:
    alerts = [sample.alert for sample in samples]
    budget = CallBudget(len(alerts))
    provider = NaiveMock(budget) if naive else WellBehavedMock(budget)
    result = run_pipeline(alerts, provider, budget, config=config, seed=seed)
    return ConfigRun(
        config=config,
        provider=result.provider,
        prompt_version=result.prompt_version,
        canary=new_canary(seed),
        outcomes=result.outcomes,
    )


def run_eval(samples: Sequence[Sample], seed: str = SEED) -> EvalRun:
    """The full ablation over ``samples``: deterministic for a given ``seed``."""
    return EvalRun(
        seed=seed,
        samples=tuple(samples),
        naive=tuple(run_config(samples, config, naive=True, seed=seed) for config in DefenseConfig),
        well_behaved_all=run_config(samples, DefenseConfig.ALL, naive=False, seed=seed),
    )
