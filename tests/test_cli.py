from __future__ import annotations

import sys
from pathlib import Path

import pytest

from netwatch import __version__
from netwatch.__main__ import main


def test_version(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "venv"))  # not inside a release
    with pytest.raises(SystemExit) as exc:
        main(["--version"], environ={})
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"netwatch {__version__}"


def test_version_from_a_shell_shows_the_release_revision(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Regression: the CLI run from a shell (no NETWATCH_REVISION) showed no revision.
    (tmp_path / "revision.env").write_text("NETWATCH_REVISION=0123456789abcdef0123\n")
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "venv"))
    with pytest.raises(SystemExit):
        main(["--version"], environ={})
    assert capsys.readouterr().out.strip() == f"netwatch {__version__} (revision 0123456789ab)"


def test_version_shows_deployed_revision(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"], environ={"NETWATCH_REVISION": "0123456789abcdef0123"})
    assert capsys.readouterr().out.strip() == f"netwatch {__version__} (revision 0123456789ab)"


def test_missing_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([], environ={}) == 2
    err = capsys.readouterr().err
    assert "a command is required" in err
    assert "Traceback" not in err


def test_unknown_command_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["frobnicate"], environ={})
    assert exc.value.code == 2
