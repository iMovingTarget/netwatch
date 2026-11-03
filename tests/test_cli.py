from __future__ import annotations

import sys
from contextlib import closing
from pathlib import Path

import pytest

from netwatch import __version__, notify, storage
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


def test_notify_commands_need_a_chat_id(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["notify", "test"], environ={"NETWATCH_STATE_DIR": str(tmp_path)}) == 2
    assert "NETWATCH_TELEGRAM_CHAT_ID" in capsys.readouterr().err


def test_notify_chats_without_a_token_says_where_it_looked(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    env = {"NETWATCH_TELEGRAM_TOKEN_FILE": str(tmp_path / "token")}
    assert main(["notify", "chats"], environ=env) == 2
    err = capsys.readouterr().err
    assert f"no Telegram bot token at {tmp_path / 'token'}" in err
    assert "Traceback" not in err


def test_notify_status_before_and_after_the_first_start(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    env = {"NETWATCH_STATE_DIR": str(tmp_path), "NETWATCH_TELEGRAM_CHAT_ID": "42"}
    storage.connect(tmp_path / "netwatch.db").close()
    assert main(["notify", "status"], environ=env) == 0
    assert "netwatch-notify has not run yet" in capsys.readouterr().out
    with closing(storage.connect(tmp_path / "netwatch.db")) as conn:
        storage.set_meta(conn, notify.BASELINE_KEY, "1793000000000000")
    assert main(["notify", "status"], environ=env) == 0
    out = capsys.readouterr().out
    assert "notifications:  on, chat 42" in out
    assert "alerts:         0 sent, 0 suppressed, 0 summarised" in out
    assert "waiting:        0" in out


# Found in the v0.6.0 audit: -n -1 meant "no limit" (SQLite reads LIMIT -1 that way), 0 printed
# nothing, and a port or an hour count too large for C ended in a Python traceback.
@pytest.mark.parametrize(
    "argv",
    [
        ["dns", "recent", "-n", "-1"],
        ["dns", "recent", "-n", "0"],
        ["dns", "top", "-n", "-5"],
        ["dns", "top", "--hours", "0"],
        ["dns", "top", "--hours", "99999999999999"],
        ["auth", "recent", "-n", "-1"],
        ["alerts", "-n", "0"],
        ["alerts", "-n", "ten"],
        ["dns", "check", "--server", "192.0.2.53", "--port", "70000"],
        ["dns", "check", "--server", "192.0.2.53", "--port", "0"],
    ],
)
def test_numbers_out_of_range_are_usage_errors(
    argv: list[str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv, environ={"NETWATCH_STATE_DIR": str(tmp_path)})
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "must be a whole number from 1 to" in err
    assert "Traceback" not in err


# Found in the v0.6.0 audit: a label over 63 characters ended in a UnicodeError traceback, and an
# empty label (a..example) sent a malformed query that the resolver never answered.
@pytest.mark.parametrize(
    "name", ["a" * 64 + ".example", "a..example", "", ".", "a." * 127 + "example"]
)
def test_dns_check_rejects_names_that_are_not_dns_names(
    name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["dns", "check", "--server", "192.0.2.53", "--name", name]
    assert main(argv, environ={}) == 2
    err = capsys.readouterr().err
    assert "is not a DNS name" in err
    assert "Traceback" not in err
