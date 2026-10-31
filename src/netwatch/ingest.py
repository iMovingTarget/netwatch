"""Follow dnsmasq's journal and store every DNS query.

Restarts must not lose queries. The ingester saves a cursor in the same transaction as the
queries it stores: the position of the oldest query still waiting for its answer, or of the last
line read when nothing is waiting. On start it asks journalctl to begin at that cursor
(inclusive), so a query that was half-read is read again in full. Queries that were already
stored come round again too, and are ignored (see dnsdb.store). The reading itself is in
netwatch.journal.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from netwatch import dnsdb, journal, storage
from netwatch.config import Settings
from netwatch.dnslog import DnsQuery, QueryAssembler
from netwatch.errors import NetwatchError

CURSOR_KEY = "dns.journal_cursor"
HEARTBEAT_KEY = "dns.heartbeat_us"
DNSMASQ_UNIT = "dnsmasq.service"
DB_NAME = "netwatch.db"

log = logging.getLogger("netwatch.ingest")


def journal_command(cursor: str | None, unit: str = DNSMASQ_UNIT) -> list[str]:
    """The journalctl invocation that streams ``unit``'s log from ``cursor`` (or from now)."""
    # Inclusive: the cursor marks the first line of a query that may not be stored yet.
    return journal.command([f"--unit={unit}"], cursor, inclusive=True)


def _wall_us() -> int:
    return time.time_ns() // 1000


class Ingester:
    """Feed journal lines to a QueryAssembler and commit finished queries with the cursor."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        assembler: QueryAssembler,
        retention_days: int,
        wall_us: Callable[[], int] = _wall_us,
    ) -> None:
        self._conn = conn
        self._assembler = assembler
        self._retention_days = retention_days
        self._wall_us = wall_us
        self._done: list[DnsQuery] = []
        self._latest_us = 0
        self._last_cursor: str | None = None
        self.saved_cursor = storage.get_meta(conn, CURSOR_KEY)

    def handle(self, line: bytes) -> None:
        record = journal.parse_record(line)
        if record is None:
            return
        self._done += self._assembler.feed(*record)
        self._latest_us = max(self._latest_us, record.ts_us)
        self._last_cursor = record.cursor
        # While lines are flowing, time is the log's own time, so a backlog read in a burst
        # still gives multi-line answers their settle time.
        self._done += self._assembler.flush(self._latest_us)

    def idle(self) -> None:
        """Nothing new arrived for a while: let real time settle the pending answers."""
        self._done += self._assembler.flush(max(self._latest_us, self._wall_us()))

    def commit(self) -> int:
        """Store finished queries and the resume cursor in one transaction. Returns rows added."""
        cursor = self._assembler.resume_cursor() or self._last_cursor
        if not self._done and cursor == self.saved_cursor:
            return 0
        with storage.transaction(self._conn):
            added = dnsdb.store(self._conn, self._done)
            if cursor is not None:
                storage.put_meta(self._conn, CURSOR_KEY, cursor)
        self._done = []
        self.saved_cursor = cursor
        return added

    def heartbeat(self) -> None:
        storage.set_meta(self._conn, HEARTBEAT_KEY, str(self._wall_us()))

    def prune(self) -> int:
        cutoff = self._wall_us() - self._retention_days * 86_400 * 1_000_000
        with storage.transaction(self._conn):
            pruned = dnsdb.prune(self._conn, cutoff)
        if pruned:
            log.info("deleted %d queries older than %d days", pruned, self._retention_days)
        return pruned


def import_file(settings: Settings, path: Path) -> int:
    """Store the queries in a saved ``journalctl -o json`` export. Returns how many were new.

    For trying Netwatch without dnsmasq (examples/dnsmasq-journal.jsonl) and for loading a log
    exported from another host. The saved cursor is left alone: it belongs to the live journal.
    """
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise NetwatchError(f"cannot read {path}: {exc.strerror}") from exc
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    with closing(storage.connect(settings.state_dir / DB_NAME)) as conn:
        assembler = QueryAssembler(settings.blocklist_dir.as_posix())
        done: list[DnsQuery] = []
        for line in lines:
            record = journal.parse_record(line)
            if record is not None:
                done += assembler.feed(*record)
        done += assembler.flush_all()
        with storage.transaction(conn):
            return dnsdb.store(conn, done)


def run(
    settings: Settings,
    stop: threading.Event,
    command: list[str] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Follow the journal until ``stop`` is set. Returns the exit code."""
    with closing(storage.connect(settings.state_dir / DB_NAME)) as conn:
        assembler = QueryAssembler(settings.blocklist_dir.as_posix())
        ingester = Ingester(conn, assembler, settings.dns_retention_days)
        cmd = command or journal_command(ingester.saved_cursor)
        log.info(
            "following %s from %s",
            DNSMASQ_UNIT,
            "the saved position" if ingester.saved_cursor else "now",
        )
        stored = journal.follow(cmd, ingester, stop, monotonic)
        log.info("stopped after storing %d queries", stored)
        return 0
