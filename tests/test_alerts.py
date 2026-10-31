from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from netwatch import alerts, storage
from netwatch.alerts import Alert
from netwatch.authlog import ALERT_KINDS, KIND_BRUTE_FORCE


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / "nw.db")) as c:
        yield c


def _alert(ts_us: int, kind: str = KIND_BRUTE_FORCE, subject: str = "203.0.113.5") -> Alert:
    return Alert(ts_us, kind, "warning", subject, f"alert {ts_us}")


def test_recent_is_newest_first_and_filters_by_kind(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        assert alerts.store(conn, [_alert(1), _alert(2, kind="new-device")]) == 2
    stored = alerts.recent(conn, 10)
    assert [(a.ts_us, a.kind, a.notified_us) for a in stored] == [
        (2, "new-device", None),
        (1, KIND_BRUTE_FORCE, None),
    ]
    assert [a.kind for a in alerts.recent(conn, 10, kinds=ALERT_KINDS)] == [KIND_BRUTE_FORCE]


def test_subjects_since_for_restoring_a_detector(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        alerts.store(conn, [_alert(2), _alert(7), _alert(8, kind="other-kind")])
    assert alerts.subjects_since(conn, KIND_BRUTE_FORCE, 3) == [("203.0.113.5", 7)]


def test_prune_leaves_other_detectors_alerts_alone(conn: sqlite3.Connection) -> None:
    with storage.transaction(conn):
        alerts.store(conn, [_alert(1), _alert(1, kind="new-device"), _alert(10)])
    with storage.transaction(conn):
        assert alerts.prune(conn, 5, ALERT_KINDS) == 1
    assert sorted((a.kind, a.ts_us) for a in alerts.recent(conn, 10)) == [
        ("new-device", 1),
        (KIND_BRUTE_FORCE, 10),
    ]
    assert storage.deleted_counts(conn, "alerts") == {(KIND_BRUTE_FORCE, "warning"): 1}
