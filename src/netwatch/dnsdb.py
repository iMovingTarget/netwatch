"""Store and query DNS queries in the Netwatch database."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import astuple

from netwatch import storage
from netwatch.dnslog import STATUS_BLOCKED, DnsQuery

_COLUMNS = "ts_us, serial, client, name, qtype, status, answer, upstream"


def store(conn: sqlite3.Connection, queries: Iterable[DnsQuery]) -> int:
    """Insert queries, skipping any already stored. Returns how many were new.

    Call inside storage.transaction() together with saving the journal cursor, so the rows and
    the position they were read up to are committed together.
    """
    before = conn.total_changes
    conn.executemany(
        f"INSERT OR IGNORE INTO dns_queries ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (astuple(q) for q in queries),
    )
    return conn.total_changes - before


def prune(conn: sqlite3.Connection, older_than_us: int) -> int:
    """Delete queries logged before ``older_than_us``. Returns how many were deleted."""
    return storage.delete_counted(conn, "dns_queries", ("status",), "ts_us < ?", (older_than_us,))


def recent(
    conn: sqlite3.Connection,
    limit: int,
    client: str | None = None,
    blocked_only: bool = False,
) -> list[DnsQuery]:
    """The newest queries first, optionally for one client or only blocked ones."""
    where, params = _filters(client=client, blocked_only=blocked_only)
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM dns_queries {where} ORDER BY ts_us DESC, serial DESC LIMIT ?",
        (*params, limit),
    )
    return [DnsQuery(*row) for row in rows]


def status_counts(conn: sqlite3.Connection, since_us: int) -> dict[str, int]:
    rows = conn.execute(
        "SELECT status, count(*) FROM dns_queries WHERE ts_us >= ? GROUP BY status", (since_us,)
    )
    return dict(rows.fetchall())


def top_names(
    conn: sqlite3.Connection, since_us: int, limit: int, blocked_only: bool = False
) -> list[tuple[str, int]]:
    where, params = _filters(since_us=since_us, blocked_only=blocked_only)
    rows = conn.execute(
        f"SELECT name, count(*) AS n FROM dns_queries {where}"
        " GROUP BY name ORDER BY n DESC, name LIMIT ?",
        (*params, limit),
    )
    return rows.fetchall()


def top_clients(conn: sqlite3.Connection, since_us: int, limit: int) -> list[tuple[str, int, int]]:
    """(client, queries, blocked queries), busiest first."""
    rows = conn.execute(
        "SELECT client, count(*) AS n, sum(status = ?) FROM dns_queries WHERE ts_us >= ?"
        " GROUP BY client ORDER BY n DESC, client LIMIT ?",
        (STATUS_BLOCKED, since_us, limit),
    )
    return rows.fetchall()


def _filters(
    client: str | None = None, since_us: int | None = None, blocked_only: bool = False
) -> tuple[str, tuple[object, ...]]:
    clauses: list[str] = []
    params: list[object] = []
    if blocked_only:
        clauses.append("status = ?")
        params.append(STATUS_BLOCKED)
    if since_us is not None:
        clauses.append("ts_us >= ?")
        params.append(since_us)
    if client is not None:
        clauses.append("client = ?")
        params.append(client)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, tuple(params)
