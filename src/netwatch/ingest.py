"""Follow dnsmasq's journal and store every DNS query.

journalctl does the reading: ``journalctl --unit=dnsmasq.service --output=json --follow`` gives one
JSON object per log entry, with the message, its time and a cursor (an opaque position in the
journal). Running it as a child process needs no Python bindings for libsystemd, and the service
only needs read access to the journal (the systemd-journal group), not root.

Restarts must not lose queries. The ingester saves a cursor in the same transaction as the
queries it stores: the position of the oldest query still waiting for its answer, or of the last
line read when nothing is waiting. On start it asks journalctl to begin at that cursor
(inclusive), so a query that was half-read is read again in full. Queries that were already
stored come round again too, and are ignored (see dnsdb.store).
"""

from __future__ import annotations

import json
import logging
import os
import selectors
import sqlite3
import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from netwatch import dnsdb, storage
from netwatch.config import Settings
from netwatch.dnslog import DnsQuery, QueryAssembler
from netwatch.errors import NetwatchError

CURSOR_KEY = "dns.journal_cursor"
DNSMASQ_UNIT = "dnsmasq.service"
DB_NAME = "netwatch.db"
COMMIT_INTERVAL_S = 1.0
PRUNE_INTERVAL_S = 3600.0
READ_TIMEOUT_S = 1.0

log = logging.getLogger("netwatch.ingest")


def journal_command(cursor: str | None, unit: str = DNSMASQ_UNIT) -> list[str]:
    """The journalctl invocation that streams ``unit``'s log from ``cursor`` (or from now)."""
    cmd = ["journalctl", f"--unit={unit}", "--output=json", "--all", "--follow", "--no-pager"]
    # --cursor is inclusive (unlike --after-cursor); see the module docstring for why.
    cmd.append(f"--cursor={cursor}" if cursor else "--lines=0")
    return cmd


def parse_record(line: bytes) -> tuple[str, int, str] | None:
    """(message, time in microseconds, cursor) from one line of ``journalctl -o json``."""
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    message = record.get("MESSAGE")
    if isinstance(message, list):  # journald exports non-UTF-8 messages as a byte array
        message = bytes(message).decode("utf-8", "replace")
    cursor = record.get("__CURSOR")
    timestamp = record.get("__REALTIME_TIMESTAMP")
    if not isinstance(message, str) or not cursor or not timestamp:
        return None
    return message, int(timestamp), cursor


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
        self._retention_us = retention_days * 86_400 * 1_000_000
        self._wall_us = wall_us
        self._done: list[DnsQuery] = []
        self._latest_us = 0
        self._last_cursor: str | None = None
        self.saved_cursor = storage.get_meta(conn, CURSOR_KEY)

    def handle(self, line: bytes) -> None:
        parsed = parse_record(line)
        if parsed is None:
            return
        message, ts_us, cursor = parsed
        self._done += self._assembler.feed(message, ts_us, cursor)
        self._latest_us = max(self._latest_us, ts_us)
        self._last_cursor = cursor
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

    def prune(self) -> int:
        with storage.transaction(self._conn):
            return dnsdb.prune(self._conn, self._wall_us() - self._retention_us)


class _LineReader:
    """Read whole lines from a pipe, waiting at most ``timeout`` seconds for new data.

    Reads the file descriptor directly: a buffered file object can hold complete lines that
    select() doesn't know about, which would delay them until the next write.
    """

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._buffer = b""
        self._selector = selectors.DefaultSelector()
        self._selector.register(fd, selectors.EVENT_READ)

    def read(self, timeout: float) -> list[bytes] | None:
        """New complete lines (possibly none), or None at end of file."""
        if not self._selector.select(timeout):
            return []
        chunk = os.read(self._fd, 65536)
        if not chunk:
            return None
        *lines, self._buffer = (self._buffer + chunk).split(b"\n")
        return lines

    def close(self) -> None:
        self._selector.close()


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
            parsed = parse_record(line)
            if parsed is not None:
                done += assembler.feed(*parsed)
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
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
        except OSError as exc:
            raise NetwatchError(f"cannot run {cmd[0]}: {exc.strerror}") from exc
        assert proc.stdout is not None
        reader = _LineReader(proc.stdout.fileno())
        stored = 0
        last_commit = monotonic()
        last_prune = float("-inf")
        try:
            while not stop.is_set():
                lines = reader.read(READ_TIMEOUT_S)
                if lines is None:
                    break
                for line in lines:
                    ingester.handle(line)
                if not lines:
                    ingester.idle()
                now = monotonic()
                if now - last_commit >= COMMIT_INTERVAL_S:
                    stored += ingester.commit()
                    last_commit = now
                if now - last_prune >= PRUNE_INTERVAL_S:
                    pruned = ingester.prune()
                    if pruned:
                        log.info(
                            "deleted %d queries older than %d days",
                            pruned,
                            settings.dns_retention_days,
                        )
                    last_prune = now
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            reader.close()
            proc.stdout.close()
            # Store what finished; queries still waiting are re-read from the saved cursor.
            stored += ingester.commit()
        if not stop.is_set():
            raise NetwatchError(f"{cmd[0]} exited unexpectedly with code {proc.returncode}")
        log.info("stopped after storing %d queries", stored)
        return 0
