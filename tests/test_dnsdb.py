from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from netwatch import dnsdb, storage
from netwatch.dnslog import DnsQuery

BASE = DnsQuery(
    ts_us=1_000_000,
    serial=1,
    client="192.0.2.10",
    name="example.com",
    qtype="A",
    status="forwarded",
    answer="192.0.2.80",
    upstream="198.51.100.1",
)


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / "nw.db")) as c:
        yield c


def _q(n: int, **changes: object) -> DnsQuery:
    return replace(BASE, ts_us=BASE.ts_us + n, serial=n, **changes)


def test_store_is_idempotent(conn: sqlite3.Connection) -> None:
    queries = [_q(1), _q(2)]
    with storage.transaction(conn):
        assert dnsdb.store(conn, queries) == 2
    with storage.transaction(conn):
        assert dnsdb.store(conn, [*queries, _q(3)]) == 1
    assert [q.serial for q in dnsdb.recent(conn, 10)] == [3, 2, 1]


def test_same_serial_after_a_dnsmasq_restart_is_a_new_query(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        dnsdb.store(conn, [BASE, replace(BASE, ts_us=BASE.ts_us + 5_000_000)])
    assert len(dnsdb.recent(conn, 10)) == 2


def test_recent_filters_and_round_trips(conn: sqlite3.Connection) -> None:
    blocked = _q(
        2,
        client="192.0.2.11",
        name="ads.example.com",
        status="blocked",
        answer="0.0.0.0",
        upstream=None,
    )
    with storage.transaction(conn):
        dnsdb.store(conn, [_q(1), blocked, _q(3)])
    assert dnsdb.recent(conn, 10, blocked_only=True) == [blocked]
    assert dnsdb.recent(conn, 10, client="192.0.2.11") == [blocked]
    assert [q.serial for q in dnsdb.recent(conn, 2)] == [3, 2]


def test_prune_deletes_only_older_rows(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        dnsdb.store(conn, [_q(1), _q(2), _q(3)])
        assert dnsdb.prune(conn, older_than_us=BASE.ts_us + 3) == 2
    assert [q.serial for q in dnsdb.recent(conn, 10)] == [3]


def test_prune_remembers_what_it_deleted_by_status(conn: sqlite3.Connection) -> None:
    # Regression: the query counters are rows stored plus rows pruned; without the running
    # total, retention made them drop and Prometheus saw a counter reset.
    blocked = _q(2, name="ads.example.com", status="blocked", answer="0.0.0.0", upstream=None)
    with storage.transaction(conn):
        dnsdb.store(conn, [_q(1), blocked, _q(3)])
        dnsdb.prune(conn, older_than_us=BASE.ts_us + 3)
    assert storage.deleted_counts(conn, "dns_queries") == {("forwarded",): 1, ("blocked",): 1}


def test_counts_and_tops(conn: sqlite3.Connection) -> None:
    rows = [
        _q(1),
        _q(2),
        _q(3, name="ads.example.com", status="blocked", answer="0.0.0.0", upstream=None),
        _q(4, client="192.0.2.11", name="ads.example.com", status="blocked", answer="::"),
        _q(5, client="192.0.2.11", name="example.org", status="cached"),
        _q(0, name="old.example"),  # before the window
    ]
    with storage.transaction(conn):
        dnsdb.store(conn, rows)
    since = BASE.ts_us + 1
    assert dnsdb.status_counts(conn, since) == {"forwarded": 2, "blocked": 2, "cached": 1}
    assert dnsdb.top_names(conn, since, 2) == [("ads.example.com", 2), ("example.com", 2)]
    assert dnsdb.top_names(conn, since, 5, blocked_only=True) == [("ads.example.com", 2)]
    assert dnsdb.top_clients(conn, since, 5) == [("192.0.2.10", 3, 1), ("192.0.2.11", 2, 1)]


def test_migration_from_version_1_keeps_meta(tmp_path: Path) -> None:
    db = tmp_path / "nw.db"
    with closing(sqlite3.connect(db)) as raw:
        raw.executescript(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "INSERT INTO meta VALUES ('skeleton.revision', 'abc');"
            "PRAGMA user_version = 1;"
        )
    with closing(storage.connect(db)) as conn:
        assert storage.schema_version(conn) == storage.SCHEMA_VERSION
        assert storage.get_meta(conn, "skeleton.revision") == "abc"
        assert dnsdb.recent(conn, 1) == []
