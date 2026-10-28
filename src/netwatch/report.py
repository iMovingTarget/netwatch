"""Plain-text reports of stored DNS queries for the terminal (ASCII only)."""

from __future__ import annotations

import sqlite3
from datetime import datetime, tzinfo

from netwatch import dnsdb
from netwatch.dnslog import DnsQuery

_STATUS_ORDER = ("forwarded", "cached", "blocked", "local", "no-answer")


def _time(ts_us: int, tz: tzinfo | None) -> str:
    return datetime.fromtimestamp(ts_us / 1_000_000, tz).strftime("%Y-%m-%d %H:%M:%S")


def recent_table(queries: list[DnsQuery], tz: tzinfo | None = None) -> str:
    """Oldest first, so the newest line ends up next to the prompt."""
    if not queries:
        return "no queries stored yet\n"
    rows = [("TIME", "CLIENT", "TYPE", "STATUS", "NAME", "ANSWER")]
    for q in reversed(queries):
        rows.append(
            (_time(q.ts_us, tz), q.client, q.qtype, q.status, q.name, _ascii(q.answer or "-"))
        )
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    lines = []
    for row in rows:
        cells = [cell.ljust(width) for cell, width in zip(row[:5], widths, strict=True)]
        lines.append("  ".join([*cells, row[5]]).rstrip())
    return "\n".join(lines) + "\n"


def summary(conn: sqlite3.Connection, since_us: int, hours: int, limit: int) -> str:
    counts = dnsdb.status_counts(conn, since_us)
    total = sum(counts.values())
    lines = [f"Last {hours} h: {total} queries"]
    if total:
        parts = [
            f"{counts[s]} {s} ({100 * counts[s] / total:.1f}%)"
            for s in _STATUS_ORDER
            if s in counts
        ]
        lines.append("  " + ", ".join(parts))
    for title, rows in (
        ("Most blocked names", dnsdb.top_names(conn, since_us, limit, blocked_only=True)),
        ("Most queried names", dnsdb.top_names(conn, since_us, limit)),
    ):
        lines += ["", f"{title}:"]
        lines += [f"  {count:>7}  {_ascii(name)}" for name, count in rows] or ["  (none)"]
    lines += ["", "Busiest clients:", f"  {'queries':>7}  {'blocked':>7}  client"]
    clients = dnsdb.top_clients(conn, since_us, limit)
    lines += [f"  {n:>7}  {b:>7}  {client}" for client, n, b in clients] or ["  (none)"]
    return "\n".join(lines) + "\n"


def _ascii(text: str) -> str:
    # Console output may be redirected on Windows; non-ASCII would raise there.
    return text.encode("ascii", "backslashreplace").decode("ascii")
