"""Canary (D9): exact, spaced, case-changed, split-across-fields, and deterministic under a seed."""

from __future__ import annotations

import pytest

from ai_security_assistant.detector.canary import (
    CANARY_ALPHABET,
    CANARY_LENGTH,
    CANARY_PREFIX,
    canary_leaked,
    new_canary,
)

CANARY = new_canary(seed=11)


def test_seeded_canary_is_deterministic_and_shaped() -> None:
    assert new_canary(seed=11) == CANARY
    assert new_canary(seed=12) != CANARY
    assert new_canary(seed="a") == new_canary(seed="a")
    assert CANARY.startswith(CANARY_PREFIX)
    assert len(CANARY) == len(CANARY_PREFIX) + CANARY_LENGTH
    assert set(CANARY[len(CANARY_PREFIX) :]) <= set(CANARY_ALPHABET)


def test_unseeded_canary_differs_per_run() -> None:
    assert new_canary() != new_canary()


def test_exact_match() -> None:
    assert canary_leaked(CANARY, [f"the token is {CANARY}."])


def test_no_match_in_clean_text() -> None:
    assert not canary_leaked(CANARY, ["severity high", "", "CNRY and some other text"])
    assert not canary_leaked(CANARY, [])


def test_case_changed() -> None:
    assert canary_leaked(CANARY, [CANARY.lower()])
    assert canary_leaked(CANARY, [CANARY.swapcase()])


@pytest.mark.parametrize("separator", [" ", "-", "_", ".", "  ", "\n", "\t", "​", "/ "])
def test_separators_between_characters(separator: str) -> None:
    assert canary_leaked(CANARY, [separator.join(CANARY)])
    assert canary_leaked(CANARY, [separator.join(CANARY.lower())])


def test_spaced_canary_word() -> None:
    assert canary_leaked(CANARY, ["C A N A R Y: " + " ".join(CANARY)])


def test_hidden_and_lookalike_characters() -> None:
    hidden = "​".join(CANARY)
    assert canary_leaked(CANARY, [hidden])
    lookalike = CANARY.replace("C", "С").replace("B", "В")  # Cyrillic Es and Ve
    assert lookalike != CANARY
    assert canary_leaked(CANARY, [lookalike])
    assert canary_leaked(CANARY, ["Ｃ" + CANARY[1:]])  # full-width C, folded by NFKC


def test_split_across_two_fields() -> None:
    half = len(CANARY) // 2
    assert canary_leaked(CANARY, ["head " + CANARY[:half], CANARY[half:] + " tail"])
    assert canary_leaked(CANARY, ["x", CANARY[:3], CANARY[3:9], CANARY[9:]])


def test_a_partial_canary_is_not_a_leak() -> None:
    assert not canary_leaked(CANARY, [CANARY[:-1]])
    half = len(CANARY) // 2
    assert not canary_leaked(CANARY, [CANARY[:half], "other", CANARY[half:]])


def test_a_too_short_canary_is_refused() -> None:
    with pytest.raises(ValueError, match="too short"):
        canary_leaked("abc", ["abc"])
