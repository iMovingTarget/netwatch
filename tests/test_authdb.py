from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from netwatch import authdb, storage
from netwatch.authlog import ALERT_KINDS, KIND_BRUTE_FORCE, Alert, AuthEvent


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / "nw.db")) as c:
        yield c


def _event(ts_us: int, source: str = "203.0.113.5", outcome: str = "failed") -> AuthEvent:
    return AuthEvent(
        ts_us=ts_us,
        source=source,
        username="root",
        outcome=outcome,
        method=None if outcome == "failed" else "publickey",
        invalid_user=False,
        message=f"message {ts_us}",
        cursor=f"cursor-{ts_us}",
    )


def _alert(ts_us: int, kind: str = KIND_BRUTE_FORCE, subject: str = "203.0.113.5") -> Alert:
    return Alert(ts_us, kind, "warning", subject, f"alert {ts_us}")


def test_events_are_stored_once(conn: sqlite3.Connection) -> None:
    events = [_event(1), _event(2), _event(3, "192.0.2.10", "accepted")]
    with storage.transaction(conn):
        assert authdb.store_events(conn, events) == 3
    with storage.transaction(conn):
        assert authdb.store_events(conn, events) == 0  # the same journal entries again
    assert authdb.recent(conn, 10) == list(reversed(events))


def test_recent_filters(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        authdb.store_events(
            conn, [_event(1), _event(2, "198.51.100.7"), _event(3, outcome="accepted")]
        )
    assert [e.ts_us for e in authdb.recent(conn, 10, failed_only=True)] == [2, 1]
    assert [e.ts_us for e in authdb.recent(conn, 10, source="198.51.100.7")] == [2]
    assert [e.ts_us for e in authdb.recent(conn, 1)] == [3]


def test_window_queries_for_restoring_the_monitor(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        authdb.store_events(conn, [_event(1), _event(5), _event(6, outcome="accepted")])
        authdb.store_alerts(conn, [_alert(2), _alert(7), _alert(8, kind="other-kind")])
    assert authdb.failures_since(conn, 2) == [("203.0.113.5", 5)]
    assert authdb.alert_subjects_since(conn, KIND_BRUTE_FORCE, 3) == [("203.0.113.5", 7)]


def test_alerts_newest_first_and_by_kind(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        assert authdb.store_alerts(conn, [_alert(1), _alert(2, kind="device-new")]) == 2
    stored = authdb.alerts(conn, 10)
    assert [(a.ts_us, a.kind, a.notified_us) for a in stored] == [
        (2, "device-new", None),
        (1, KIND_BRUTE_FORCE, None),
    ]
    assert [a.kind for a in authdb.alerts(conn, 10, kinds=ALERT_KINDS)] == [KIND_BRUTE_FORCE]


def test_prune_leaves_other_detectors_alerts_alone(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        authdb.store_events(conn, [_event(1), _event(10)])
        authdb.store_alerts(conn, [_alert(1), _alert(1, kind="device-new"), _alert(10)])
    with storage.transaction(conn):
        assert authdb.prune(conn, 5, ALERT_KINDS) == 2
    assert [e.ts_us for e in authdb.recent(conn, 10)] == [10]
    assert sorted((a.kind, a.ts_us) for a in authdb.alerts(conn, 10)) == [
        ("device-new", 1),
        (KIND_BRUTE_FORCE, 10),
    ]
