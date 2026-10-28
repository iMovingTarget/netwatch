"""Store and query SSH login events and alerts in the Netwatch database."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from netwatch.authlog import OUTCOME_FAILED, Alert, AuthEvent

_EVENT_COLUMNS = "ts_us, source, username, outcome, method, invalid_user, message, cursor"
_ALERT_COLUMNS = "ts_us, kind, severity, subject, message"


@dataclass(frozen=True)
class StoredAlert:
    id: int
    ts_us: int
    kind: str
    severity: str
    subject: str
    message: str
    notified_us: int | None


def store_events(conn: sqlite3.Connection, events: Iterable[AuthEvent]) -> int:
    """Insert events, skipping journal entries already stored. Returns how many were new.

    Call inside storage.transaction() together with saving the journal cursor.
    """
    before = conn.total_changes
    conn.executemany(
        f"INSERT OR IGNORE INTO auth_events ({_EVENT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            (
                e.ts_us,
                e.source,
                e.username,
                e.outcome,
                e.method,
                int(e.invalid_user),
                e.message,
                e.cursor,
            )
            for e in events
        ),
    )
    return conn.total_changes - before


def store_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert]) -> int:
    before = conn.total_changes
    conn.executemany(
        f"INSERT INTO alerts ({_ALERT_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
        ((a.ts_us, a.kind, a.severity, a.subject, a.message) for a in alerts),
    )
    return conn.total_changes - before


def recent(
    conn: sqlite3.Connection,
    limit: int,
    source: str | None = None,
    failed_only: bool = False,
) -> list[AuthEvent]:
    """The newest events first, optionally from one address or only failures."""
    clauses, params = [], []
    if source is not None:
        clauses.append("source = ?")
        params.append(source)
    if failed_only:
        clauses.append("outcome = ?")
        params.append(OUTCOME_FAILED)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"SELECT {_EVENT_COLUMNS} FROM auth_events {where} ORDER BY ts_us DESC, id DESC LIMIT ?",
        (*params, limit),
    )
    return [
        AuthEvent(ts, src, user, outcome, method, bool(invalid), message, cursor)
        for ts, src, user, outcome, method, invalid, message, cursor in rows
    ]


def failures_since(conn: sqlite3.Connection, since_us: int) -> list[tuple[str, int]]:
    """(address, time) of every failure since ``since_us``, oldest first."""
    rows = conn.execute(
        "SELECT source, ts_us FROM auth_events WHERE outcome = ? AND ts_us >= ? ORDER BY ts_us, id",
        (OUTCOME_FAILED, since_us),
    )
    return rows.fetchall()


def alert_subjects_since(
    conn: sqlite3.Connection, kind: str, since_us: int
) -> list[tuple[str, int]]:
    """(subject, time) of alerts of ``kind`` since ``since_us``, oldest first."""
    rows = conn.execute(
        "SELECT subject, ts_us FROM alerts WHERE kind = ? AND ts_us >= ? ORDER BY ts_us, id",
        (kind, since_us),
    )
    return rows.fetchall()


def alerts(
    conn: sqlite3.Connection, limit: int, kinds: Sequence[str] | None = None
) -> list[StoredAlert]:
    """The newest alerts first, optionally only of some kinds."""
    where, params = "", ()
    if kinds:
        where = f"WHERE kind IN ({', '.join('?' * len(kinds))})"
        params = tuple(kinds)
    rows = conn.execute(
        f"SELECT id, {_ALERT_COLUMNS}, notified_us FROM alerts {where}"
        " ORDER BY ts_us DESC, id DESC LIMIT ?",
        (*params, limit),
    )
    return [StoredAlert(*row) for row in rows]


def prune(conn: sqlite3.Connection, older_than_us: int, alert_kinds: Sequence[str]) -> int:
    """Delete login events, and alerts of ``alert_kinds``, from before ``older_than_us``."""
    deleted = conn.execute("DELETE FROM auth_events WHERE ts_us < ?", (older_than_us,)).rowcount
    deleted += conn.execute(
        f"DELETE FROM alerts WHERE ts_us < ? AND kind IN ({', '.join('?' * len(alert_kinds))})",
        (older_than_us, *alert_kinds),
    ).rowcount
    return deleted
