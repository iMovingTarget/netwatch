from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

import netwatch
from netwatch import dnsdb, ingest, storage
from netwatch.__main__ import main
from netwatch.config import load_settings
from netwatch.dnslog import QueryAssembler
from netwatch.errors import NetwatchError

FIXTURE = Path(__file__).parent / "fixtures" / "dnsmasq-journal.jsonl"
BLOCKLIST_DIR = "/var/lib/netwatch-blocklist"
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="pipes and signals")


def _lines() -> list[bytes]:
    return FIXTURE.read_bytes().splitlines()


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / ingest.DB_NAME)) as c:
        yield c


def _ingester(conn: sqlite3.Connection) -> ingest.Ingester:
    # A wall clock far after the fixture, so idle() settles everything.
    return ingest.Ingester(conn, QueryAssembler(BLOCKLIST_DIR), 30, wall_us=lambda: 2**62)


def test_journal_command() -> None:
    base = [
        "journalctl",
        "--unit=dnsmasq.service",
        "--output=json",
        "--all",
        "--follow",
        "--no-pager",
    ]
    assert ingest.journal_command(None) == [*base, "--lines=0"]
    assert ingest.journal_command("s=abc;i=1") == [*base, "--cursor=s=abc;i=1"]


def test_ingester_stores_every_query_once(conn: sqlite3.Connection) -> None:
    ingester = _ingester(conn)
    for line in _lines():
        ingester.handle(line)
    ingester.idle()
    assert ingester.commit() == 17
    last_cursor = json.loads(_lines()[-1])["__CURSOR"]
    assert storage.get_meta(conn, ingest.CURSOR_KEY) == last_cursor

    # Reading the same lines again (as after a restart) adds nothing.
    again = _ingester(conn)
    for line in _lines():
        again.handle(line)
    again.idle()
    assert again.commit() == 0
    assert len(dnsdb.recent(conn, 100)) == 17


def test_cursor_stays_at_an_unfinished_query(conn: sqlite3.Connection) -> None:
    lines = _lines()
    # Stop right after the query line of serial 1, before its answer.
    first_query = next(i for i, line in enumerate(lines) if b"query[A] example.com" in line)
    ingester = _ingester(conn)
    for line in lines[: first_query + 1]:
        ingester.handle(line)
    assert ingester.commit() == 0
    assert storage.get_meta(conn, ingest.CURSOR_KEY) == json.loads(lines[first_query])["__CURSOR"]


def test_prune_uses_the_retention_period(conn: sqlite3.Connection) -> None:
    ingester = ingest.Ingester(
        conn, QueryAssembler(BLOCKLIST_DIR), retention_days=1, wall_us=lambda: 2**62
    )
    for line in _lines():
        ingester.handle(line)
    ingester.idle()
    ingester.commit()
    assert ingester.prune() == 17


def _write_fake_journal(path: Path, then: str) -> list[str]:
    script = path / "fake_journal.py"
    script.write_text(
        textwrap.dedent(
            f"""
            import sys, time
            sys.stdout.buffer.write(open({str(FIXTURE)!r}, "rb").read())
            sys.stdout.flush()
            {then}
            """
        )
    )
    return [sys.executable, str(script)]


@POSIX_ONLY
def test_run_stores_queries_and_reports_an_unexpected_exit(tmp_path: Path) -> None:
    settings = load_settings({"NETWATCH_STATE_DIR": str(tmp_path)})
    command = _write_fake_journal(tmp_path, then="")
    with pytest.raises(NetwatchError, match="exited unexpectedly"):
        ingest.run(settings, threading.Event(), command=command)
    with closing(storage.connect(tmp_path / ingest.DB_NAME)) as conn:
        # The lines arrive in one burst, so only answers that had settled in log time are
        # final: 16 of 17. The last query (after the restart) waits at the saved cursor.
        assert len(dnsdb.recent(conn, 100)) == 16
        last_query = next(
            json.loads(line)["__CURSOR"]
            for line in reversed(_lines())
            if b"query[A] example.com" in line
        )
        assert storage.get_meta(conn, ingest.CURSOR_KEY) == last_query
        # The loop records a heartbeat on its first pass, not only when queries arrive.
        assert storage.get_meta(conn, ingest.HEARTBEAT_KEY) is not None


@POSIX_ONLY
def test_service_stores_everything_and_stops_cleanly_on_sigterm(tmp_path: Path) -> None:
    # Run the real CLI with a fake journalctl first on PATH that prints the fixture and waits.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "journalctl"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import sys, time\n"
        f"sys.stdout.buffer.write(open({str(FIXTURE)!r}, 'rb').read())\n"
        "sys.stdout.flush()\n"
        "time.sleep(60)\n"
    )
    fake.chmod(0o755)
    src_dir = Path(netwatch.__file__).resolve().parent.parent
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "PYTHONPATH": str(src_dir),
        "NETWATCH_STATE_DIR": str(tmp_path),
        "NETWATCH_ENV_FILE": str(tmp_path / "no-such.env"),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "netwatch", "dns", "ingest"], env=env, stderr=subprocess.PIPE
    )
    db = tmp_path / ingest.DB_NAME
    try:
        deadline = time.monotonic() + 20
        count = 0
        while time.monotonic() < deadline and count < 17:
            time.sleep(0.5)
            if db.exists():
                with closing(storage.connect(db)) as conn:
                    count = len(dnsdb.recent(conn, 100))
        assert count == 17  # the idle flush settled the last answers in real time
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
    err = proc.stderr.read().decode() if proc.stderr else ""
    assert "following dnsmasq.service from now" in err
    assert "stopped after storing 17 queries" in err


def test_import_file_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = {"NETWATCH_STATE_DIR": str(tmp_path / "state")}
    assert main(["dns", "ingest", "--from-file", str(FIXTURE)], environ=env) == 0
    assert capsys.readouterr().out.strip() == f"stored 17 new queries from {FIXTURE}"
    assert main(["dns", "ingest", "--from-file", str(FIXTURE)], environ=env) == 0
    assert capsys.readouterr().out.startswith("stored 0 new queries")
    assert main(["dns", "ingest", "--from-file", str(tmp_path / "missing.jsonl")], environ=env) == 1
    assert capsys.readouterr().err.startswith("netwatch: cannot read")
