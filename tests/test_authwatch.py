from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from netwatch import alerts, authdb, authwatch, storage
from netwatch.__main__ import main
from netwatch.authlog import KIND_BRUTE_FORCE, AuthMonitor
from netwatch.config import load_settings
from netwatch.errors import NetwatchError
from netwatch.ingest import DB_NAME

# Real OpenSSH 10.2 log, anonymised: eight failed logins from 203.0.113.5 in about four seconds,
# between key logins as alice from 192.0.2.10 (see fixtures/README.md).
FIXTURE = Path(__file__).parent / "fixtures" / "sshd-journal.jsonl"
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="pipes and executables")


def _lines() -> list[bytes]:
    return FIXTURE.read_bytes().splitlines()


def _end_us() -> int:
    return int(json.loads(_lines()[-1])["__REALTIME_TIMESTAMP"])


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / DB_NAME)) as c:
        yield c


def _ingest(conn: sqlite3.Connection, monitor: AuthMonitor) -> authwatch.AuthIngester:
    ingester = authwatch.AuthIngester(conn, monitor, retention_days=90)
    for line in _lines():
        ingester.handle(line)
    return ingester


def test_real_log_gives_one_alert_and_every_login(conn: sqlite3.Connection) -> None:
    ingester = _ingest(conn, AuthMonitor(max_failures=5, window_minutes=10))
    assert ingester.commit() == 12  # 8 failures and 4 key logins

    failed = authdb.recent(conn, 100, failed_only=True)
    assert len(failed) == 8
    assert {(e.source, e.invalid_user) for e in failed} == {("203.0.113.5", True)}
    logins = [e for e in authdb.recent(conn, 100) if e.outcome == "accepted"]
    assert {(e.source, e.username, e.method) for e in logins} == {
        ("192.0.2.10", "alice", "publickey")
    }
    [alert] = alerts.recent(conn, 10)
    assert (alert.kind, alert.subject) == (KIND_BRUTE_FORCE, "203.0.113.5")
    assert "latest as 'nwtest5'" in alert.message  # raised by the fifth failure
    assert storage.get_meta(conn, authwatch.CURSOR_KEY) == json.loads(_lines()[-1])["__CURSOR"]


def test_restart_restores_the_window_from_the_database(conn: sqlite3.Connection) -> None:
    settings = load_settings({})
    _ingest(conn, AuthMonitor(5, 10)).commit()
    # A restarted service that saw the same lines again (it shouldn't: it resumes after the
    # cursor) stores nothing new and doesn't repeat the alert: the restored window still holds
    # the failures and the alert's cooldown.
    again = _ingest(conn, authwatch.new_monitor(conn, settings, now_us=_end_us()))
    assert again.commit() == 0
    assert len(alerts.recent(conn, 10)) == 1


def test_nothing_to_commit_is_a_no_op(conn: sqlite3.Connection) -> None:
    ingester = authwatch.AuthIngester(conn, AuthMonitor(5, 10), retention_days=90)
    assert ingester.commit() == 0
    assert storage.get_meta(conn, authwatch.CURSOR_KEY) is None


def test_prune_uses_the_retention_period(conn: sqlite3.Connection) -> None:
    ingester = _ingest(conn, AuthMonitor(5, 10))
    ingester.commit()
    keep = authwatch.AuthIngester(conn, AuthMonitor(5, 10), 1, wall_us=lambda: _end_us())
    assert keep.prune() == 0
    later = authwatch.AuthIngester(conn, AuthMonitor(5, 10), 1, wall_us=lambda: 2**62)
    assert later.prune() == 13  # 12 events and the alert


def test_import_file_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = {"NETWATCH_STATE_DIR": str(tmp_path / "state")}
    assert main(["auth", "watch", "--from-file", str(FIXTURE)], environ=env) == 0
    assert capsys.readouterr().out.strip() == (
        f"stored 12 new login events from {FIXTURE}, 1 alert"
    )
    assert main(["auth", "watch", "--from-file", str(FIXTURE)], environ=env) == 0
    assert capsys.readouterr().out.strip().startswith("stored 0 new login events")
    with closing(storage.connect(tmp_path / "state" / DB_NAME)) as conn:
        assert len(alerts.recent(conn, 10)) == 1  # importing again doesn't repeat alerts
    missing = str(tmp_path / "missing.jsonl")
    assert main(["auth", "watch", "--from-file", missing], environ=env) == 1


@POSIX_ONLY
def test_run_follows_sshd_and_resumes_after_the_saved_cursor(tmp_path: Path) -> None:
    # A fake journalctl that records its arguments, prints the capture (after --after-cursor,
    # like the real one) and exits.
    args_file = tmp_path / "args.json"
    fake = tmp_path / "journalctl"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"open({str(args_file)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
        f"lines = open({str(FIXTURE)!r}, 'rb').read().splitlines(keepends=True)\n"
        "after = [a.split('=', 1)[1] for a in sys.argv if a.startswith('--after-cursor=')]\n"
        "if after:\n"
        "    cursors = [json.loads(line)['__CURSOR'] for line in lines]\n"
        "    lines = lines[cursors.index(after[0]) + 1 :]\n"
        "sys.stdout.buffer.write(b''.join(lines))\n"
    )
    fake.chmod(0o755)
    os.environ["PATH"] = f"{tmp_path}{os.pathsep}{os.environ['PATH']}"
    settings = load_settings({"NETWATCH_STATE_DIR": str(tmp_path)})
    try:
        with pytest.raises(NetwatchError, match="exited unexpectedly"):
            authwatch.run(settings, threading.Event())
        first = json.loads(args_file.read_text())
        assert first[:2] == ["--identifier=sshd", "--identifier=sshd-session"]
        assert first[-1] == "--lines=0"

        with pytest.raises(NetwatchError, match="exited unexpectedly"):
            authwatch.run(settings, threading.Event())
        last_cursor = json.loads(_lines()[-1])["__CURSOR"]
        assert json.loads(args_file.read_text())[-1] == f"--after-cursor={last_cursor}"
    finally:
        os.environ["PATH"] = os.environ["PATH"].split(os.pathsep, 1)[1]
    with closing(storage.connect(tmp_path / DB_NAME)) as conn:
        assert len(authdb.recent(conn, 100)) == 12
        assert len(alerts.recent(conn, 10)) == 1
        assert storage.get_meta(conn, authwatch.HEARTBEAT_KEY) is not None
