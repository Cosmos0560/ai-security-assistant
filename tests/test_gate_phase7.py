"""Phase 7 gate: ``--full`` (PLAN section 6). The release run itself (wheel build, venv, PyPI
install) is exercised by running ``gate.py --full``; these tests cover its pure parts and the
command line, without building or installing anything."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import ModuleType

import pytest

import ai_security_assistant


def test_the_gate_reads_the_package_version(gate: ModuleType) -> None:
    text = gate.INIT_FILE.read_text(encoding="utf-8")
    assert gate.package_version(text) == ai_security_assistant.__version__


@pytest.mark.parametrize("text", ['__version__ = "1.0"', "__version__ = '1.0.0'", ""])
def test_a_missing_or_odd_version_is_refused(gate: ModuleType, text: str) -> None:
    with pytest.raises(ValueError, match="no __version__"):
        gate.package_version(text)


def good_wheel(gate: ModuleType, version: str = "1.0.0") -> list[str]:
    return [
        *gate.WHEEL_MUST_CONTAIN,
        f"{gate.PACKAGE}/__init__.py",
        f"{gate.PACKAGE}-{version}.dist-info/METADATA",
    ]


def test_a_complete_wheel_passes(gate: ModuleType) -> None:
    assert gate.wheel_problems(good_wheel(gate), "1.0.0") == []
    assert gate.wheel_name("1.0.0") == "ai_security_assistant-1.0.0-py3-none-any.whl"


def test_a_wheel_without_the_dataset_fails(gate: ModuleType) -> None:
    names = [n for n in good_wheel(gate) if not n.endswith("alerts.jsonl")]
    assert gate.wheel_problems(names, "1.0.0") == [
        f"wheel lacks {gate.PACKAGE}/data/eval/alerts.jsonl"
    ]


def test_a_wheel_with_the_wrong_version_fails(gate: ModuleType) -> None:
    problems = gate.wheel_problems(good_wheel(gate, "0.1.0"), "1.0.0")
    assert problems == [f"wheel lacks {gate.PACKAGE}-1.0.0.dist-info/METADATA"]


@pytest.mark.parametrize(
    "extra",
    ["tests/test_cli.py", "examples/demo/access.log", "graphify-out/graph.json", "x/y.pyc"],
)
def test_a_wheel_with_stray_files_fails(gate: ModuleType, extra: str) -> None:
    assert gate.wheel_problems([*good_wheel(gate), extra], "1.0.0") == [
        f"wheel must not contain {extra}"
    ]


def test_venv_executables_per_platform(gate: ModuleType) -> None:
    venv = Path("v")
    assert gate.venv_bin(venv, "aisa", windows=True) == venv / "Scripts" / "aisa.exe"
    assert gate.venv_bin(venv, "aisa", windows=False) == venv / "bin" / "aisa"


def test_the_release_runs_never_see_a_key(gate: ModuleType) -> None:
    key_name = "ANTHROPIC" + "_API_KEY"
    env = {key_name: "x", "AISA_LIVE": "1", "PATH": "p"}
    assert gate.smoke_env(env) == {"PATH": "p"}


def test_expect_exit_reports_the_last_line(gate: ModuleType) -> None:
    ok = subprocess.CompletedProcess(["x"], 0, "", "")
    bad = subprocess.CompletedProcess(["x"], 1, "", "first\nlast line\n")
    silent = subprocess.CompletedProcess(["x"], 5, "", "")
    assert gate.expect_exit(ok, 0, "w") == []
    assert gate.expect_exit(bad, 0, "w") == ["w: exit 1, expected 0 (last line)"]
    assert gate.expect_exit(silent, 2, "w") == ["w: exit 5, expected 2 ((no output))"]


def test_the_command_line(gate: ModuleType) -> None:
    parser = gate.build_parser()
    assert parser.parse_args([]).full is False
    full = parser.parse_args(["--full", "--release-python", "py311"])
    assert full.full is True and full.release_python == "py311"
    for flag in (["--live"], ["-m", "live"], ["--full", "--live"]):
        with pytest.raises(SystemExit) as exc:
            gate.main(flag)
        assert exc.value.code == 2


def test_the_smoke_fixtures_exist(gate: ModuleType) -> None:
    assert gate.SMOKE_TRIAGED.is_file()
    assert gate.SMOKE_REVIEW.is_file()
    assert gate.RELEASE_VENV == gate.ROOT / ".venv-release"


def test_the_release_venv_is_ignored(gate: ModuleType) -> None:
    probe = subprocess.run(
        ["git", "check-ignore", "-q", ".venv-release/probe"], cwd=gate.ROOT, check=False
    )
    assert probe.returncode == 0
