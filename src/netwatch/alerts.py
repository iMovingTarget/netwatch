"""Alerts from every detector, in the one table they share.

Each detector writes its alerts here: the SSH login monitor, the LAN device scan and the notifier
itself (restarts of the host, test messages). ``netwatch alerts`` reads them, and the notifier
(netwatch-notify) sends each one to Telegram and records in ``notified_us`` when it dealt with it.
Keeping them in one table gives the notifier a single place to look.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from netwatch import storage

SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"

_COLUMNS = "ts_us, kind, severity, subject, message"


@dataclass(frozen=True)
class Alert:
    ts_us: int
    kind: str
    severity: str
    subject: str  # what the alert is about: a client address, a device's MAC address
    message: str


@dataclass(frozen=True)
class StoredAlert:
    id: int
    ts_us: int
    kind: str
    severity: str
    subject: str
    message: str
    notified_us: int | None


def store(conn: sqlite3.Connection, alerts: Iterable[Alert]) -> int:
    """Insert alerts. Returns how many. Call inside storage.transaction()."""
    before = conn.total_changes
    conn.executemany(
        f"INSERT INTO alerts ({_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
        ((a.ts_us, a.kind, a.severity, a.subject, a.message) for a in alerts),
    )
    return conn.total_changes - before


def add(conn: sqlite3.Connection, alert: Alert) -> int:
    """Insert one alert and return its id. Call inside storage.transaction()."""
    cursor = conn.execute(
        f"INSERT INTO alerts ({_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
        (alert.ts_us, alert.kind, alert.severity, alert.subject, alert.message),
    )
    return int(cursor.lastrowid or 0)


def get(conn: sqlite3.Connection, alert_id: int) -> StoredAlert | None:
    row = conn.execute(
        f"SELECT id, {_COLUMNS}, notified_us FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    return None if row is None else StoredAlert(*row)


def unsent(conn: sqlite3.Connection, since_us: int, limit: int) -> list[StoredAlert]:
    """Alerts from ``since_us`` on that the notifier has not dealt with yet, oldest first."""
    rows = conn.execute(
        f"SELECT id, {_COLUMNS}, notified_us FROM alerts"
        " WHERE notified_us IS NULL AND ts_us >= ? ORDER BY ts_us, id LIMIT ?",
        (since_us, limit),
    )
    return [StoredAlert(*row) for row in rows]


def unsent_summary(conn: sqlite3.Connection, since_us: int) -> tuple[int, int | None]:
    """(how many alerts wait to be sent, when the oldest of them was raised)."""
    count, oldest = conn.execute(
        "SELECT count(*), min(ts_us) FROM alerts WHERE notified_us IS NULL AND ts_us >= ?",
        (since_us,),
    ).fetchone()
    return int(count), oldest


def mark_notified(conn: sqlite3.Connection, ids: Iterable[int], ts_us: int) -> None:
    """Record that the notifier dealt with these alerts. Call inside storage.transaction()."""
    conn.executemany(
        "UPDATE alerts SET notified_us = ? WHERE id = ? AND notified_us IS NULL",
        ((ts_us, alert_id) for alert_id in ids),
    )


def subjects_since(conn: sqlite3.Connection, kind: str, since_us: int) -> list[tuple[str, int]]:
    """(subject, time) of alerts of ``kind`` since ``since_us``, oldest first."""
    rows = conn.execute(
        "SELECT subject, ts_us FROM alerts WHERE kind = ? AND ts_us >= ? ORDER BY ts_us, id",
        (kind, since_us),
    )
    return rows.fetchall()


def recent(
    conn: sqlite3.Connection, limit: int, kinds: Sequence[str] | None = None
) -> list[StoredAlert]:
    """The newest alerts first, optionally only of some kinds."""
    where, params = "", ()
    if kinds:
        where = f"WHERE kind IN ({', '.join('?' * len(kinds))})"
        params = tuple(kinds)
    rows = conn.execute(
        f"SELECT id, {_COLUMNS}, notified_us FROM alerts {where}"
        " ORDER BY ts_us DESC, id DESC LIMIT ?",
        (*params, limit),
    )
    return [StoredAlert(*row) for row in rows]


def prune(conn: sqlite3.Connection, older_than_us: int, kinds: Sequence[str]) -> int:
    """Delete alerts of ``kinds`` from before ``older_than_us``; each detector prunes its own."""
    return storage.delete_counted(
        conn,
        "alerts",
        ("kind", "severity"),
        f"ts_us < ? AND kind IN ({', '.join('?' * len(kinds))})",
        (older_than_us, *kinds),
    )
