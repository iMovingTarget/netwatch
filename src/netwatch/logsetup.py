"""Logging to stderr, with journald priorities when running under systemd.

Services log to stderr and let journald store the lines; no log files to rotate or protect. By
default journald files every stderr line at the same priority. systemd parses a "<N>" syslog
priority prefix on each line (SyslogLevelPrefix=, on by default), so under systemd each record
gets one and ``journalctl -u netwatch-... -p warning`` shows only warnings and errors.

systemd sets JOURNAL_STREAM to the device and inode of the journal stream it connected to stderr.
The variable is inherited by child processes, so its presence alone proves nothing: a command run
from a shell inside any systemd service sees it too. As systemd.exec(5) recommends, we only trust it
when it matches the device and inode of the stream we are actually writing to.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Mapping
from typing import TextIO

# Python level -> syslog priority (RFC 5424): 2 crit, 3 err, 4 warning, 6 info, 7 debug.
_SYSLOG_PRIORITY = {
    logging.CRITICAL: 2,
    logging.ERROR: 3,
    logging.WARNING: 4,
    logging.INFO: 6,
    logging.DEBUG: 7,
}


class JournalFormatter(logging.Formatter):
    """Prefix each record with its syslog priority; journald adds the timestamp itself."""

    def __init__(self) -> None:
        super().__init__("%(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        priority = _SYSLOG_PRIORITY.get(record.levelno, 6)
        return f"<{priority}>{super().format(record)}"


def is_journal_stream(stream: TextIO, environ: Mapping[str, str]) -> bool:
    """True if ``stream`` is the journal connection that JOURNAL_STREAM describes."""
    try:
        device, inode = (int(part) for part in environ.get("JOURNAL_STREAM", "").split(":"))
        info = os.fstat(stream.fileno())
    except (ValueError, OSError):
        # Unset or malformed variable, or a stream with no file descriptor (e.g. StringIO).
        return False
    return (info.st_dev, info.st_ino) == (device, inode)


def configure(level: str, environ: Mapping[str, str], stream: TextIO | None = None) -> None:
    """Send all netwatch logging to ``stream`` (stderr by default) at ``level``."""
    target = stream if stream is not None else sys.stderr
    handler = logging.StreamHandler(target)
    if is_journal_stream(target, environ):
        handler.setFormatter(JournalFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%H:%M:%S")
        )
    root = logging.getLogger("netwatch")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
