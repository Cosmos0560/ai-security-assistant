from __future__ import annotations

import pytest

from ai_security_assistant import __version__
from ai_security_assistant.cli import build_parser, main


def test_version_flag_prints_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"aisa {__version__}"


def test_no_arguments_prints_help_and_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: aisa" in capsys.readouterr().out


def test_unknown_flag_is_rejected() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--no-such-flag"])
    assert exc.value.code == 2


def test_parser_program_name() -> None:
    assert build_parser().prog == "aisa"
