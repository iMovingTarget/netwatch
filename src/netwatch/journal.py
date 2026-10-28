"""Follow a slice of the systemd journal and feed it to a consumer, resuming from a saved cursor.

journalctl does the reading: ``journalctl --output=json --follow`` gives one JSON object per log
entry, with the message, its time and a cursor (an opaque position in the journal). Running it as
a child process needs no Python bindings for libsystemd, and a service only needs read access to
the journal (the systemd-journal group), not root.

A consumer saves its cursor in the same transaction as the rows it stores, so after a restart it
carries on where it stopped, without gaps. Whether to resume at the saved entry (inclusive) or
after it depends on the consumer: see ``command``.
"""

from __future__ import annotations

import json
import logging
import os
import selectors
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from typing import NamedTuple, Protocol

from netwatch.errors import NetwatchError

COMMIT_INTERVAL_S = 1.0
PRUNE_INTERVAL_S = 3600.0
READ_TIMEOUT_S = 1.0

log = logging.getLogger("netwatch.journal")


class Record(NamedTuple):
    """One journal entry: its message, when it was logged and its cursor."""

    message: str
    ts_us: int  # microseconds since the Unix epoch
    cursor: str


class Consumer(Protocol):
    def handle(self, line: bytes) -> None:
        """One line of journalctl output (a JSON object)."""

    def idle(self) -> None:
        """Nothing new arrived for a while."""

    def commit(self) -> int:
        """Store what is finished, with the resume cursor. Returns the rows added."""

    def prune(self) -> int:
        """Delete rows past their retention period. Returns how many were deleted."""


def command(matches: Sequence[str], cursor: str | None, inclusive: bool) -> list[str]:
    """The journalctl invocation that streams the entries ``matches`` selects.

    ``matches`` are journalctl options such as ``--unit=dnsmasq.service``. Without a cursor it
    starts at the end of the journal. ``inclusive`` resumes at the saved entry itself
    (``--cursor``), for a consumer whose cursor marks something it hasn't finished; otherwise it
    resumes after it (``--after-cursor``).
    """
    cmd = ["journalctl", *matches, "--output=json", "--all", "--follow", "--no-pager"]
    if cursor is None:
        cmd.append("--lines=0")
    else:
        cmd.append(f"--cursor={cursor}" if inclusive else f"--after-cursor={cursor}")
    return cmd


def parse_record(line: bytes) -> Record | None:
    """The message, time and cursor of one line of ``journalctl -o json``, or None."""
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
    return Record(message, int(timestamp), cursor)


class LineReader:
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


def follow(
    cmd: list[str],
    consumer: Consumer,
    stop: threading.Event,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Run ``cmd`` and feed its lines to ``consumer`` until ``stop`` is set.

    Commits every COMMIT_INTERVAL_S and prunes every PRUNE_INTERVAL_S (and once at the start).
    Returns the rows added. Raises NetwatchError if the command exits on its own.
    """
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
    except OSError as exc:
        raise NetwatchError(f"cannot run {cmd[0]}: {exc.strerror}") from exc
    assert proc.stdout is not None
    reader = LineReader(proc.stdout.fileno())
    stored = 0
    last_commit = monotonic()
    last_prune = float("-inf")
    try:
        while not stop.is_set():
            lines = reader.read(READ_TIMEOUT_S)
            if lines is None:
                break
            for line in lines:
                consumer.handle(line)
            if not lines:
                consumer.idle()
            now = monotonic()
            if now - last_commit >= COMMIT_INTERVAL_S:
                stored += consumer.commit()
                last_commit = now
            if now - last_prune >= PRUNE_INTERVAL_S:
                consumer.prune()
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
        # Store what finished; anything unfinished is re-read from the saved cursor.
        stored += consumer.commit()
    if not stop.is_set():
        raise NetwatchError(f"{cmd[0]} exited unexpectedly with code {proc.returncode}")
    return stored
