"""Guardrail configuration files: settings, CI workflow, ignore and attribute files."""

from __future__ import annotations

import json
import re

from tests.conftest import ROOT


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_settings_hook_registration() -> None:
    settings = json.loads(read(".claude/settings.json"))
    entries = settings["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert entries[0]["matcher"] == "Bash|PowerShell"
    command = entries[0]["hooks"][0]["command"]
    assert "pre_tool_use.py" in command
    assert command.endswith("|| exit 2")  # a crash (exit 1) must still block
    assert (ROOT / ".claude" / "hooks" / "pre_tool_use.py").is_file()


def test_settings_attribution_disabled_and_push_tag_denied() -> None:
    settings = json.loads(read(".claude/settings.json"))
    assert settings["attribution"]["commit"] == ""
    assert settings["attribution"]["pr"] == ""
    deny = set(settings["permissions"]["deny"])
    for tool in ("Bash", "PowerShell"):
        for verb in ("push", "tag"):
            assert f"{tool}(git {verb} *)" in deny


def test_ci_workflow_matches_plan() -> None:
    ci = read(".github/workflows/ci.yml")
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1" in ci
    assert "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0" in ci
    assert re.search(r"^permissions:\n  contents: read$", ci, re.MULTILINE)
    assert "windows-latest" in ci and "ubuntu-latest" in ci
    for version in ('"3.11"', '"3.12"', '"3.13"', '"3.14"'):
        assert version in ci
    assert 'pip install -e ".[dev]"' in ci
    assert "python scripts/gate.py" in ci
    for forbidden in (
        "secrets.",
        "ANTHROPIC_API_KEY",
        "pull_request_target",
        "schedule",
        "upload-artifact",
    ):
        assert forbidden not in ci
    uses = re.findall(r"uses:\s*(\S+)", ci)
    assert uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses)


def test_gitattributes_forces_lf() -> None:
    assert read(".gitattributes").strip() == "* text=auto eol=lf"


def test_gitignore_covers_required_paths() -> None:
    lines = set(read(".gitignore").splitlines())
    for entry in (".venv/", ".venv-wsl/", ".venv-release/", "build/", "dist/", "*.egg-info/",
                  "reports/", "graphify-out/"):  # fmt: skip
        assert entry in lines


def test_license_is_mit_with_name_only() -> None:
    text = read("LICENSE")
    assert text.startswith("MIT License")
    assert "Copyright (c) 2026 Otabek Yakubov\n" in text


def test_pyproject_guardrails() -> None:
    import tomllib

    data = tomllib.loads(read("pyproject.toml"))
    assert data["project"]["requires-python"] == ">=3.11"
    assert data["project"]["dependencies"] == ["pydantic>=2,<3"]
    assert set(data["project"]["optional-dependencies"]) == {"dev"}
    assert data["tool"]["ruff"]["extend-exclude"] == [".venv-wsl", ".venv-release"]
    assert data["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]
    assert data["tool"]["mypy"] == {"strict": True, "files": ["src"], "python_version": "3.11"}
    assert data["tool"]["coverage"]["run"]["source"] == ["ai_security_assistant"]
