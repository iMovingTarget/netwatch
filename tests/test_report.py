from __future__ import annotations

from contextlib import closing
from datetime import UTC
from pathlib import Path

import pytest

from netwatch import dnsdb, ingest, report, storage
from netwatch.__main__ import main
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
