from __future__ import annotations

from contextlib import closing
from datetime import UTC
from pathlib import Path

import pytest

from netwatch import alerts, authdb, dnsdb, ingest, report, storage
from netwatch.__main__ import main
from netwatch.alerts import Alert
from netwatch.authlog import AuthEvent
from netwatch.dnslog import DnsQuery

T0 = 1_793_188_800_000_000  # 2026-10-28 12:00:00 UTC in microseconds


def _queries() -> list[DnsQuery]:
    return [
        DnsQuery(
            T0, 1, "192.0.2.10", "example.com", "A", "forwarded", "192.0.2.80", "198.51.100.1"
        ),
        DnsQuery(T0 + 1_000_000, 2, "192.0.2.11", "ads.example.com", "AAAA", "blocked", "::", None),
        DnsQuery(
            T0 + 2_000_000,
            3,
            "192.0.2.10",
            "nosuch.example",
            "A",
            "forwarded",
            "NXDOMAIN",
            "198.51.100.1",
        ),
    ]


def test_recent_table_is_aligned_oldest_first() -> None:
    newest_first = list(reversed(_queries()))
    assert report.recent_table(newest_first, tz=UTC).splitlines() == [
        "TIME                 CLIENT      TYPE  STATUS     NAME             ANSWER",
        "2026-10-28 12:00:00  192.0.2.10  A     forwarded  example.com      192.0.2.80",
        "2026-10-28 12:00:01  192.0.2.11  AAAA  blocked    ads.example.com  ::",
        "2026-10-28 12:00:02  192.0.2.10  A     forwarded  nosuch.example   NXDOMAIN",
    ]


def test_recent_and_top_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = {"NETWATCH_STATE_DIR": str(tmp_path)}
    assert main(["dns", "recent"], environ=env) == 1
    assert "no database" in capsys.readouterr().err

    with closing(storage.connect(tmp_path / ingest.DB_NAME)) as conn, storage.transaction(conn):
        dnsdb.store(conn, _queries())

    assert main(["dns", "recent", "--blocked"], environ=env) == 0
    out = capsys.readouterr().out
    assert "ads.example.com" in out
    assert "192.0.2.80" not in out  # the forwarded query is filtered out

    with closing(storage.connect(tmp_path / ingest.DB_NAME)) as conn:
        text = report.summary(conn, since_us=0, hours=24, limit=5)
    assert "Last 24 h: 3 queries" in text
    assert "2 forwarded (66.7%), 1 blocked (33.3%)" in text
    assert "        1  ads.example.com" in text
    assert "        2        0  192.0.2.10" in text


def _auth_events() -> list[AuthEvent]:
    def event(ts: int, source: str, user: str, outcome: str, invalid: bool) -> AuthEvent:
        method = "publickey" if outcome == "accepted" else None
        return AuthEvent(T0 + ts, source, user, outcome, method, invalid, "m", f"c{ts}")

    return [
        event(0, "203.0.113.5", "admin", "failed", True),
        event(1_000_000, "203.0.113.5", "root", "failed", False),
        event(2_000_000, "192.0.2.10", "alice", "accepted", False),
    ]


def test_auth_table_is_aligned_oldest_first() -> None:
    newest_first = list(reversed(_auth_events()))
    assert report.auth_table(newest_first, tz=UTC).splitlines() == [
        "TIME                 SOURCE       RESULT    METHOD     USER",
        "2026-10-28 12:00:00  203.0.113.5  failed    -          admin (no such user)",
        "2026-10-28 12:00:01  203.0.113.5  failed    -          root",
        "2026-10-28 12:00:02  192.0.2.10   accepted  publickey  alice",
    ]
    assert report.auth_table([]) == "no SSH logins stored yet\n"


def test_usernames_cannot_send_terminal_escapes() -> None:
    hostile = AuthEvent(T0, "203.0.113.5", "\x1b[2Jrooté", "failed", None, True, "m", "c")
    line = report.auth_table([hostile], tz=UTC).splitlines()[1]
    assert line.endswith("\\x1b[2Jroot\\xe9 (no such user)")
    assert line.isascii() and "\x1b" not in line


def test_auth_recent_and_alerts_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = {"NETWATCH_STATE_DIR": str(tmp_path)}
    assert main(["alerts"], environ=env) == 1
    assert "no database" in capsys.readouterr().err

    with closing(storage.connect(tmp_path / ingest.DB_NAME)) as conn, storage.transaction(conn):
        authdb.store_events(conn, _auth_events())
        alerts.store(
            conn, [Alert(T0 + 3, "ssh-brute-force", "warning", "203.0.113.5", "5 or more ...")]
        )

    assert main(["auth", "recent", "--failed"], environ=env) == 0
    out = capsys.readouterr().out
    assert "admin (no such user)" in out
    assert "alice" not in out
    assert main(["auth", "recent", "--source", "192.0.2.10", "-n", "1"], environ=env) == 0
    assert len(capsys.readouterr().out.splitlines()) == 2
    assert main(["alerts"], environ=env) == 0
    [_, row] = capsys.readouterr().out.splitlines()
    assert "warning   ssh-brute-force  5 or more ..." in row
