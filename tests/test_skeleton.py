from __future__ import annotations

import os
import queue
import signal
import subprocess
import sys
import threading
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

import netwatch
from netwatch import skeleton, storage
from netwatch.__main__ import main
from netwatch.config import Settings, load_settings

FIXED_NOW = datetime(2026, 10, 27, 20, 0, 0, tzinfo=UTC)


def _settings(state_dir: Path, revision: str | None = "abc123") -> Settings:
    env = {"NETWATCH_STATE_DIR": str(state_dir)}
    if revision:
        env["NETWATCH_REVISION"] = revision
    return load_settings(env)


def test_run_records_start_and_returns_when_stopped(tmp_path: Path) -> None:
    stop = threading.Event()
    stop.set()
    state = tmp_path / "state"

    assert skeleton.run(_settings(state), stop, clock=lambda: FIXED_NOW) == 0

    with closing(storage.connect(state / skeleton.DB_NAME)) as conn:
        assert storage.get_meta(conn, "skeleton.last_start") == "2026-10-27T20:00:00+00:00"
        assert storage.get_meta(conn, "skeleton.revision") == "abc123"


def test_unusable_state_dir_is_a_one_line_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("")

    assert main(["skeleton"], environ={"NETWATCH_STATE_DIR": str(not_a_dir)}) == 1

    err = capsys.readouterr().err
    assert err.startswith("netwatch: cannot create state directory")
    assert "Traceback" not in err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_service_stops_cleanly_on_signal(tmp_path: Path, signum: signal.Signals) -> None:
    src_dir = Path(netwatch.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(src_dir), "NETWATCH_STATE_DIR": str(tmp_path)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "netwatch", "skeleton"],
        env=env,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines: queue.Queue[str] = queue.Queue()
    reader = threading.Thread(target=lambda: [lines.put(line) for line in proc.stderr or []])
    reader.start()
    try:
        assert "netwatch.skeleton: started" in lines.get(timeout=15)
        proc.send_signal(signum)
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        reader.join(timeout=5)
    assert lines.get(timeout=5).rstrip().endswith("netwatch.skeleton: stopped")
