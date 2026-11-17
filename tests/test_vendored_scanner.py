"""Smoke tests for the vendored secret-scanner v1.0.0 (D19). The vendored code is excluded from
the coverage figure; these tests show that what was copied works as a string scanner.

Every fake secret is built at runtime by the scanner's own fake builder, which joins fragments
stored apart (D30).
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

from ai_security_assistant.third_party import secret_scanner
from ai_security_assistant.third_party.secret_scanner.core import fakes
from ai_security_assistant.third_party.secret_scanner.core.detect.engine import Engine
from ai_security_assistant.third_party.secret_scanner.core.detect.entropy import EntropyConfig
from ai_security_assistant.third_party.secret_scanner.core.errors import ConfigError
from ai_security_assistant.third_party.secret_scanner.core.models import Rule
from ai_security_assistant.third_party.secret_scanner.core.rules import parse_rules_document
from ai_security_assistant.validator.secrets import builtin_rules, engine

VENDOR_DIR = Path(secret_scanner.__file__).parent
EXPECTED_RULES = {
    "aws-access-key-id",
    "aws-secret-access-key",
    "github-token",
    "github-fine-grained-pat",
    "gitlab-pat",
    "slack-token",
    "slack-webhook-url",
    "stripe-secret-key",
    "google-api-key",
    "npm-token",
    "pypi-token",
    "sendgrid-api-key",
    "azure-storage-account-key",
}


def found(text: str) -> list[str]:
    return [match.rule_id for match in engine().scan(text.encode("utf-8")).matches]


def test_the_package_is_version_1_0_0() -> None:
    assert secret_scanner.__version__ == "1.0.0"
    version = (VENDOR_DIR / "VERSION").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert "version: v1.0.0" in version.split("\n")
    assert "commit: 314888d31965ef29014c96b6a3c171404ab86bc6" in version


def test_the_builtin_rules_load_and_are_the_upstream_set() -> None:
    rules = builtin_rules()
    assert {rule.id for rule in rules} == EXPECTED_RULES
    assert all(isinstance(rule, Rule) for rule in rules)


def test_the_rules_document_is_ascii_json_version_1() -> None:
    data = (VENDOR_DIR / "rules" / "builtin.json").read_bytes()
    assert data.isascii()
    assert json.loads(data)["version"] == 1


@pytest.mark.parametrize("rule", builtin_rules(), ids=lambda rule: rule.id)
def test_every_rule_finds_its_own_runtime_built_fake(rule: Rule) -> None:
    fake = fakes.build_fake(rule, seed="smoke")
    line = " ".join([*rule.context, "value =", fake])
    assert rule.id in found(line)


def test_a_github_token_with_a_wrong_checksum_is_still_reported_at_low_confidence() -> None:
    """Upstream behaviour, and the safe one for the validator: it still fails closed."""
    rule = next(rule for rule in builtin_rules() if rule.id == "github-token")
    good = engine().scan(fakes.build_fake(rule, seed="crc").encode()).matches
    bad = engine().scan(fakes.build_fake(rule, seed="crc", valid_checksum=False).encode()).matches
    assert [m.confidence.value for m in good] == ["high"]
    assert [m.confidence.value for m in bad] == ["low"]


def test_a_private_key_is_found() -> None:
    assert found(fakes.fake_private_key("smoke")) == ["private-key"]


def test_plain_text_and_high_entropy_hex_are_clean_with_entropy_off() -> None:
    assert found("Rule 5710 on host edge01.example.test: triaged.") == []
    assert found("sha256 " + fakes.body("smoke", "hex", 64)) == []
    assert not engine().entropy_enabled


def test_the_entropy_detector_still_works_when_switched_on() -> None:
    with_entropy = Engine(builtin_rules(), entropy=EntropyConfig())
    token = fakes.fake_entropy_token("smoke")
    result = with_entropy.scan(f"api_token = {token}".encode())
    assert [m.rule_id for m in result.matches] == ["entropy-base64"]


def test_a_bad_rules_document_is_refused() -> None:
    with pytest.raises(ConfigError):
        parse_rules_document({"version": 2, "rules": []})


def test_matches_never_show_the_secret_in_repr() -> None:
    rule = next(rule for rule in builtin_rules() if rule.id == "gitlab-pat")
    fake = fakes.build_fake(rule, seed="repr")
    matches = engine().scan(fake.encode()).matches
    assert matches and all(fake not in repr(match) for match in matches)


def _vendored_python_files() -> list[Path]:
    return sorted(VENDOR_DIR.rglob("*.py"))


def test_vendored_imports_are_relative_or_stdlib() -> None:
    """Nothing outside the vendored package and the standard library is imported."""
    for path in _vendored_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0:
                assert (node.module or "").split(".")[0] in sys.stdlib_module_names, path
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] in sys.stdlib_module_names, path


def test_vendored_code_passes_the_ast_ban(gate: object) -> None:
    files = _vendored_python_files()
    assert len(files) == 19
    for path in files:
        source = path.read_text(encoding="utf-8")
        assert gate.check_source(source, path.name) == []  # type: ignore[attr-defined]
