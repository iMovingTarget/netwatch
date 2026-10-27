from __future__ import annotations

import io
import logging

from netwatch import logsetup


def _log_lines(environ: dict[str, str], level: str = "INFO") -> list[str]:
    stream = io.StringIO()
    logsetup.configure(level, environ, stream)
    log = logging.getLogger("netwatch.test")
    log.debug("detail")
    log.info("started")
    log.warning("odd")
    log.error("broken")
    return stream.getvalue().splitlines()


def test_journal_lines_carry_syslog_priority() -> None:
    lines = _log_lines({"JOURNAL_STREAM": "8:12345"})
    assert lines == [
        "<6>netwatch.test: started",
        "<4>netwatch.test: odd",
        "<3>netwatch.test: broken",
    ]


def test_terminal_lines_have_time_and_level() -> None:
    lines = _log_lines({}, level="DEBUG")
    assert len(lines) == 4
    assert lines[0].endswith("DEBUG netwatch.test: detail")
    assert lines[1].endswith("INFO netwatch.test: started")
