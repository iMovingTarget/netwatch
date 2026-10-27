from __future__ import annotations

import io
import logging
import os
from pathlib import Path
from typing import TextIO

from netwatch import logsetup


def _emit(stream: TextIO, environ: dict[str, str], level: str = "INFO") -> None:
    logsetup.configure(level, environ, stream)
    log = logging.getLogger("netwatch.test")
    log.debug("detail")
    log.info("started")
    log.warning("odd")
    log.error("broken")


def _journal_env_for(stream: TextIO) -> dict[str, str]:
    info = os.fstat(stream.fileno())
    return {"JOURNAL_STREAM": f"{info.st_dev}:{info.st_ino}"}


def test_journal_lines_carry_syslog_priority(tmp_path: Path) -> None:
    out = tmp_path / "stderr.txt"
    with out.open("w") as stream:
        _emit(stream, _journal_env_for(stream))
    assert out.read_text().splitlines() == [
        "<6>netwatch.test: started",
        "<4>netwatch.test: odd",
        "<3>netwatch.test: broken",
    ]


def test_inherited_journal_stream_for_another_fd_is_ignored(tmp_path: Path) -> None:
    # Regression: JOURNAL_STREAM is inherited by child processes. A command run from a shell
    # inside a systemd service sees the service's value even though its own stderr is a
    # terminal or a file, and must not write "<6>" prefixes there.
    with (tmp_path / "other.txt").open("w") as other:
        inherited = _journal_env_for(other)
    out = tmp_path / "stderr.txt"
    with out.open("w") as stream:
        _emit(stream, inherited)
    assert not any(line.startswith("<") for line in out.read_text().splitlines())


def test_terminal_lines_have_time_and_level() -> None:
    stream = io.StringIO()
    _emit(stream, {"JOURNAL_STREAM": "8:12345"}, level="DEBUG")
    lines = stream.getvalue().splitlines()
    assert len(lines) == 4
    assert lines[0].endswith("DEBUG netwatch.test: detail")
    assert lines[1].endswith("INFO netwatch.test: started")


def test_malformed_journal_stream_is_ignored(tmp_path: Path) -> None:
    with (tmp_path / "stderr.txt").open("w") as stream:
        assert not logsetup.is_journal_stream(stream, {"JOURNAL_STREAM": "not-a-pair"})
