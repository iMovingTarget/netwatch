"""Logging to stderr, with journald priorities when running under systemd.

Services log to stderr and let journald store the lines; no log files to rotate or protect. By
default journald files every stderr line at the same priority. systemd parses a "<N>" syslog
priority prefix on each line (SyslogLevelPrefix=, on by default), so under systemd each record
gets one and ``journalctl -u netwatch-... -p warning`` shows only warnings and errors.

systemd sets JOURNAL_STREAM when stderr is connected to the journal; that is how we detect it.
"""

from __future__ import annotations

import logging
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


def configure(level: str, environ: Mapping[str, str], stream: TextIO | None = None) -> None:
    """Send all netwatch logging to ``stream`` (stderr by default) at ``level``."""
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    if environ.get("JOURNAL_STREAM"):
        handler.setFormatter(JournalFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%H:%M:%S")
        )
    root = logging.getLogger("netwatch")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
