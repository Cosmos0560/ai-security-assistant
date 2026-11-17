"""Per-run canary (D9): system-prompt leakage as a deterministic check.

The canary is a random token placed in the system prompt. If it shows up in the model's output
the prompt leaked; no pattern matching on prose is involved. A leak is rarely byte-exact, so the
match ignores case, any separators or whitespace inserted between characters ("C a-N a R y"),
zero-width and bidi characters, and Cyrillic/Greek lookalikes, and it also finds a canary split
across two fields.
"""

from __future__ import annotations

import random
import secrets
from collections.abc import Iterable
from typing import Final

from ai_security_assistant.sanitize import fold_confusables, normalize_text

# No vowels and no easily confused characters: the token cannot spell a word, and it never
# collides with ordinary alert text by accident.
CANARY_ALPHABET: Final = "BCDFGHJKLMNPQRSTVWXZ23456789"
CANARY_PREFIX: Final = "CNRY"
CANARY_LENGTH: Final = 20
MIN_CANARY_LENGTH: Final = 12


def new_canary(seed: int | str | None = None) -> str:
    """A fresh canary. ``seed=None`` uses ``secrets``; a seed (test/mock mode) is deterministic."""
    if seed is None:
        body = "".join(secrets.choice(CANARY_ALPHABET) for _ in range(CANARY_LENGTH))
    else:
        rng = random.Random(f"aisa-canary:{seed}")
        body = "".join(rng.choice(CANARY_ALPHABET) for _ in range(CANARY_LENGTH))
    return CANARY_PREFIX + body


def _skeleton(text: str) -> str:
    """Case-folded letters and digits only, after the sanitizer's normalization."""
    folded = fold_confusables(normalize_text(text)).casefold()
    return "".join(ch for ch in folded if ch.isalnum())


def canary_leaked(canary: str, texts: Iterable[str]) -> bool:
    """True when ``canary`` appears in ``texts``, also split across consecutive texts.

    All texts are reduced to their letters and digits and joined, so a canary cut in two by a
    field boundary is found too. A canary of fewer than ``MIN_CANARY_LENGTH`` significant
    characters is refused: it would match ordinary text.
    """
    needle = _skeleton(canary)
    if len(needle) < MIN_CANARY_LENGTH:
        raise ValueError("canary is too short to be a reliable marker")
    return needle in "".join(_skeleton(text) for text in texts)
