"""Plain-text reports for the terminal (ASCII only)."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime, tzinfo

from netwatch import dnsdb
from netwatch.alerts import StoredAlert
from netwatch.authlog import AuthEvent
from netwatch.dnslog import DnsQuery

_STATUS_ORDER = ("forwarded", "cached", "blocked", "local", "no-answer")


def _time(ts_us: int, tz: tzinfo | None) -> str:
    return datetime.fromtimestamp(ts_us / 1_000_000, tz).strftime("%Y-%m-%d %H:%M:%S")


def _columns(rows: Sequence[Sequence[str]]) -> str:
    """Rows as aligned columns; the last column is left ragged."""
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]) - 1)]
    lines = []
    for row in rows:
        cells = [cell.ljust(width) for cell, width in zip(row[:-1], widths, strict=True)]
        lines.append("  ".join([*cells, row[-1]]).rstrip())
    return "\n".join(lines) + "\n"


def recent_table(queries: list[DnsQuery], tz: tzinfo | None = None) -> str:
    """Oldest first, so the newest line ends up next to the prompt."""
    if not queries:
        return "no queries stored yet\n"
    rows = [("TIME", "CLIENT", "TYPE", "STATUS", "NAME", "ANSWER")]
    for q in reversed(queries):
        rows.append(
            (_time(q.ts_us, tz), q.client, q.qtype, q.status, q.name, _ascii(q.answer or "-"))
        )
    return _columns(rows)


def auth_table(events: list[AuthEvent], tz: tzinfo | None = None) -> str:
    """SSH logins, oldest first. Usernames are chosen by clients, so they are escaped."""
    if not events:
        return "no SSH logins stored yet\n"
    rows = [("TIME", "SOURCE", "RESULT", "METHOD", "USER")]
    for e in reversed(events):
        user = _escaped(e.username) + (" (no such user)" if e.invalid_user else "")
        rows.append((_time(e.ts_us, tz), e.source, e.outcome, e.method or "-", user))
    return _columns(rows)


def alerts_table(alerts: list[StoredAlert], tz: tzinfo | None = None) -> str:
    """Alerts, oldest first."""
    if not alerts:
        return "no alerts\n"
    rows = [("TIME", "SEVERITY", "KIND", "MESSAGE")]
    for a in reversed(alerts):
        rows.append((_time(a.ts_us, tz), a.severity, a.kind, _escaped(a.message)))
    return _columns(rows)


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


def _escaped(text: str) -> str:
    """``text`` with control and non-ASCII characters escaped (\\x1b, \\xe9, ...).

    For text an outsider controls, such as an SSH username: printed raw, an escape sequence in it
    could rewrite the terminal of whoever reads the report.
    """
    return "".join(
        ch if ch.isascii() and ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
        for ch in text
    )


def _ascii(text: str) -> str:
    # Console output may be redirected on Windows; non-ASCII would raise there.
    return text.encode("ascii", "backslashreplace").decode("ascii")
