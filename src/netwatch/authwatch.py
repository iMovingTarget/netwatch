"""Follow sshd's journal, store every login and raise brute-force alerts (netwatch-auth).

Every journal line is a finished event, so the saved cursor marks the last line handled and a
restart resumes after it (unlike the DNS ingester, whose cursor marks an unfinished query).
Events, alerts and the cursor are committed in one transaction, so an alert is never stored
without the line that raised it, or the other way round.

On start the monitor's window is rebuilt from the database (see AuthMonitor.restore).
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from netwatch import alerts, authdb, journal, storage
from netwatch.alerts import Alert
from netwatch.authlog import (
    ALERT_KINDS,
    KIND_BRUTE_FORCE,
    KIND_LOGIN_AFTER_FAILURES,
    AuthEvent,
    AuthMonitor,
)
from netwatch.config import Settings
from netwatch.errors import NetwatchError
from netwatch.ingest import DB_NAME

CURSOR_KEY = "auth.journal_cursor"
# OpenSSH 9.8 and later log per-connection messages as sshd-session, earlier versions as sshd.
SSHD_MATCHES = ("--identifier=sshd", "--identifier=sshd-session")

log = logging.getLogger("netwatch.auth")


def _wall_us() -> int:
    return time.time_ns() // 1000


def new_monitor(conn: sqlite3.Connection, settings: Settings, now_us: int) -> AuthMonitor:
    """A monitor with the current window restored from the database."""
    monitor = AuthMonitor(settings.auth_max_failures, settings.auth_window_minutes)
    since_us = now_us - settings.auth_window_minutes * 60_000_000
    monitor.restore(
        failures=authdb.failures_since(conn, since_us),
        alerts=alerts.subjects_since(conn, KIND_BRUTE_FORCE, since_us),
        login_alerts=alerts.subjects_since(conn, KIND_LOGIN_AFTER_FAILURES, since_us),
    )
    return monitor


class AuthIngester:
    """Feed sshd journal lines to an AuthMonitor and commit events and alerts with the cursor."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        monitor: AuthMonitor,
        retention_days: int,
        wall_us: Callable[[], int] = _wall_us,
    ) -> None:
        self._conn = conn
        self._monitor = monitor
        self._retention_days = retention_days
        self._wall_us = wall_us
        self._events: list[AuthEvent] = []
        self._alerts: list[Alert] = []
        self._last_cursor: str | None = None
        self.saved_cursor = storage.get_meta(conn, CURSOR_KEY)

    def handle(self, line: bytes) -> None:
        record = journal.parse_record(line)
        if record is None:
            return
        event, raised = self._monitor.feed(record)
        if event is not None:
            self._events.append(event)
        self._alerts += raised
        self._last_cursor = record.cursor

    def idle(self) -> None:
        pass  # every line is complete when it arrives; nothing waits for time to pass

    def commit(self) -> int:
        """Store events, alerts and the cursor in one transaction. Returns events added."""
        cursor = self._last_cursor
        if not self._events and not self._alerts and cursor == self.saved_cursor:
            return 0
        with storage.transaction(self._conn):
            added = authdb.store_events(self._conn, self._events)
            alerts.store(self._conn, self._alerts)
            if cursor is not None:
                storage.put_meta(self._conn, CURSOR_KEY, cursor)
        for alert in self._alerts:
            log.warning("ALERT %s %s: %s", alert.severity, alert.kind, alert.message)
        self._events, self._alerts = [], []
        self.saved_cursor = cursor
        return added

    def prune(self) -> int:
        cutoff = self._wall_us() - self._retention_days * 86_400 * 1_000_000
        with storage.transaction(self._conn):
            pruned = authdb.prune(self._conn, cutoff)
            pruned += alerts.prune(self._conn, cutoff, ALERT_KINDS)
        if pruned:
            log.info(
                "deleted %d login events and alerts older than %d days",
                pruned,
                self._retention_days,
            )
        return pruned


def import_file(settings: Settings, path: Path) -> tuple[int, int]:
    """Store the logins and alerts in a saved ``journalctl -o json`` export of sshd's log.

    For trying Netwatch without a live sshd (examples/sshd-journal.jsonl) and for loading a log
    from another host. Detection runs as it would live. Returns (new events, alerts raised).
    """
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise NetwatchError(f"cannot read {path}: {exc.strerror}") from exc
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    with closing(storage.connect(settings.state_dir / DB_NAME)) as conn:
        monitor = AuthMonitor(settings.auth_max_failures, settings.auth_window_minutes)
        events: list[AuthEvent] = []
        found: list[Alert] = []
        for line in lines:
            record = journal.parse_record(line)
            if record is None:
                continue
            event, raised = monitor.feed(record)
            if event is not None:
                events.append(event)
            found += raised
        with storage.transaction(conn):
            added = authdb.store_events(conn, events)
            # Alerts don't record which line raised them, so store them only when every event
            # is new: importing a file twice, or one that overlaps, must not repeat its alerts.
            stored = alerts.store(conn, found) if added == len(events) else 0
        if found and not stored:
            log.warning("some events were already stored, so the file's alerts were not stored")
        return added, stored


def run(
    settings: Settings,
    stop: threading.Event,
    command: list[str] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Follow sshd's journal until ``stop`` is set. Returns the exit code."""
    with closing(storage.connect(settings.state_dir / DB_NAME)) as conn:
        monitor = new_monitor(conn, settings, _wall_us())
        ingester = AuthIngester(conn, monitor, settings.auth_retention_days)
        cmd = command or journal.command(SSHD_MATCHES, ingester.saved_cursor, inclusive=False)
        log.info(
            "following sshd from %s; alerting at %d failures within %d minutes",
            "the saved position" if ingester.saved_cursor else "now",
            settings.auth_max_failures,
            settings.auth_window_minutes,
        )
        stored = journal.follow(cmd, ingester, stop, monotonic)
        log.info("stopped after storing %d login events", stored)
        return 0
