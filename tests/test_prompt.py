from __future__ import annotations

import re

from ai_security_assistant.detector.canary import new_canary
from ai_security_assistant.prompt import PROMPT_VERSION, build_system_prompt, build_user_prompt
from ai_security_assistant.sanitize import sanitize_alert
from ai_security_assistant.schema import Action, Severity
from ai_security_assistant.wrap import BOUNDARY_TAG, new_nonce, unwrap
from tests import golden_cases


def read_golden(name: str) -> str:
    text = (golden_cases.GOLDEN_DIR / name).read_text(encoding="utf-8")
    return text.replace("\r\n", "\n")


def test_prompts_match_the_golden_file() -> None:
    assert golden_cases.render_prompts() == read_golden("prompts.txt")


def test_the_system_prompt_is_a_pure_function_of_the_canary() -> None:
    canary = new_canary("a")
    assert build_system_prompt(canary) == build_system_prompt(canary)
    assert build_system_prompt(canary) != build_system_prompt(new_canary("b"))


def test_the_canary_is_embedded_once() -> None:
    canary = new_canary("a")
    assert build_system_prompt(canary).count(canary) == 1


def test_the_prompt_is_versioned() -> None:
    assert PROMPT_VERSION
    assert f"version {PROMPT_VERSION}" in build_system_prompt(new_canary("a"))


def test_the_system_prompt_states_the_rules() -> None:
    prompt = build_system_prompt(new_canary("a"))
    assert "untrusted data" in prompt
    assert "never instructions" in prompt
    assert "ONE JSON object" in prompt
    assert "T#### or T####.###" in prompt
    assert "that does not appear in the alert data" in prompt
    assert f"<<<{BOUNDARY_TAG} nonce=... BEGIN>>>" in prompt
    for action in Action:
        assert f'"{action.value}"' in prompt
    for severity in Severity:
        assert f'"{severity.value}"' in prompt


def test_the_system_prompt_holds_only_the_canary_as_a_secret() -> None:
    """No nonce, no key, no per-run value other than the canary."""
    nonce = new_nonce("n")
    prompt = build_system_prompt(new_canary("a"))
    assert nonce not in prompt
    assert re.findall(r"CNRY[A-Z0-9]{20}", prompt) == [new_canary("a")]
    assert "sk-" not in prompt
    assert "ANTHROPIC" not in prompt


def test_the_user_prompt_is_exactly_the_wrap_block() -> None:
    alert = golden_cases.benign_alerts()[0]
    sanitized, _ = sanitize_alert(alert)
    nonce = new_nonce("n")
    user = build_user_prompt(sanitized, nonce)
    assert user.startswith(f"<<<{BOUNDARY_TAG} nonce={nonce} BEGIN>>>\n")
    assert user.endswith(f"\n<<<{BOUNDARY_TAG} nonce={nonce} END>>>")
    assert unwrap(user, nonce) == sanitized.fields
    assert user.count("\n") == 2  # BEGIN line, one JSON line, END line: no other text
