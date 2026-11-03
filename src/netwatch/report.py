"""Plain-text reports for the terminal (ASCII only)."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime, tzinfo

from netwatch import dnsdb
from netwatch.alerts import StoredAlert
from netwatch.authlog import AuthEvent
from netwatch.devicedb import Device
from netwatch.dnslog import DnsQuery
from netwatch.notify import Status
from netwatch.telegram import Chat

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
    """Oldest first, so the newest line ends up next to the prompt.

    Names are chosen by clients and answers by whoever runs the domain, so both are escaped.
    """
    if not queries:
        return "no queries stored yet\n"
    rows = [("TIME", "CLIENT", "TYPE", "STATUS", "NAME", "ANSWER")]
    for q in reversed(queries):
        rows.append(
            (
                _time(q.ts_us, tz),
                q.client,
                q.qtype,
                q.status,
                _escaped(q.name),
                _escaped(q.answer or "-"),
            )
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


def devices_table(
    devices: list[Device],
    last_scan_us: int | None,
    tz: tzinfo | None = None,
    count_present: bool = True,
) -> str:
    """The device inventory, by address. Labels and vendor names are escaped.

    With ``count_present``, the first line says how many of the devices answered the last scan;
    leave it off when ``devices`` is only part of the inventory.
    """
    if not devices:
        return "no devices recorded yet\n"
    lines = []
    if last_scan_us is not None:
        header = f"last scan {_time(last_scan_us, tz)}"
        if count_present:
            present = sum(d.last_seen_us >= last_scan_us for d in devices)
            header += f": {present} of {len(devices)} devices answered"
        lines.append(header)
    rows = [("IP", "MAC", "FIRST SEEN", "LAST SEEN", "STATUS", "NAME")]
    for d in devices:
        name = f"{d.label} [{_vendor(d)}]" if d.label else f"[{_vendor(d)}]"
        status = "known" if d.known else "new"
        rows.append(
            (
                d.last_ip,
                d.mac,
                _time(d.first_seen_us, tz),
                _time(d.last_seen_us, tz),
                status,
                _escaped(name),
            )
        )
    return "\n".join(lines) + ("\n" if lines else "") + _columns(rows)


def _vendor(device: Device) -> str:
    if device.local_admin:
        return "locally administered"  # a private Wi-Fi address, so no vendor
    return device.vendor or "vendor unknown"


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
        lines += [f"  {count:>7}  {_escaped(name)}" for name, count in rows] or ["  (none)"]
    lines += ["", "Busiest clients:", f"  {'queries':>7}  {'blocked':>7}  client"]
    clients = dnsdb.top_clients(conn, since_us, limit)
    lines += [f"  {n:>7}  {b:>7}  {client}" for client, n, b in clients] or ["  (none)"]
    return "\n".join(lines) + "\n"


def _escaped(text: str) -> str:
    """``text`` with control and non-ASCII characters escaped (\\x1b, \\xe9, ...).

    For text an outsider controls, such as an SSH username or a DNS name: printed raw, an escape
    sequence in it could rewrite the terminal of whoever reads the report. The result is ASCII,
    so it can also be printed to a console redirected on Windows.
    """
    return "".join(
        ch if ch.isascii() and ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
        for ch in text
    )


def notify_status(status: Status, tz: tzinfo | None = None) -> str:
    """What netwatch-notify has done so far, from the database."""
    if status.chat_id is None:
        state = "off (NETWATCH_TELEGRAM_CHAT_ID is not set)"
    elif status.baseline_us is None:
        state = f"set up for chat {status.chat_id}, but netwatch-notify has not run yet"
    else:
        state = f"on, chat {status.chat_id}"
    lines = [f"notifications:  {state}"]
    if status.baseline_us is not None:
        lines.append(f"since:          {_time(status.baseline_us, tz)} (older alerts are not sent)")
    if status.heartbeat_us is not None:
        lines.append(f"last heartbeat: {_time(status.heartbeat_us, tz)}")
    done = ", ".join(f"{count} {result}" for result, count in status.counts.items())
    lines.append(f"alerts:         {done}")
    waiting = f"{status.unsent}"
    if status.oldest_unsent_us is not None:
        waiting += f" (oldest raised {_time(status.oldest_unsent_us, tz)})"
    lines.append(f"waiting:        {waiting}")
    lines.append(f"send errors:    {status.telegram_errors}")
    return "\n".join(lines) + "\n"


def chats_table(chats: Sequence[Chat]) -> str:
    """Chats that messaged the bot. Names are chosen by Telegram users, so they are escaped."""
    rows = [("CHAT ID", "TYPE", "NAME")]
    rows += [(str(c.id), c.kind, _escaped(c.name)) for c in chats]
    return _columns(rows)
