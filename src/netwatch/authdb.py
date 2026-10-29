"""Store and query SSH login events in the Netwatch database (alerts are in netwatch.alerts)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable

from netwatch.authlog import OUTCOME_FAILED, AuthEvent

_EVENT_COLUMNS = "ts_us, source, username, outcome, method, invalid_user, message, cursor"


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


def prune(conn: sqlite3.Connection, older_than_us: int) -> int:
    """Delete login events from before ``older_than_us``. Returns how many were deleted."""
    return conn.execute("DELETE FROM auth_events WHERE ts_us < ?", (older_than_us,)).rowcount
