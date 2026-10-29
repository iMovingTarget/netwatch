from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from netwatch import storage
from netwatch.errors import StorageError


def test_new_database_uses_wal_and_current_schema(tmp_path: Path) -> None:
    with closing(storage.connect(tmp_path / "nw.db")) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert storage.schema_version(conn) == storage.SCHEMA_VERSION


def test_reopening_keeps_data(tmp_path: Path) -> None:
    db = tmp_path / "nw.db"
    with closing(storage.connect(db)) as conn:
        storage.set_meta(conn, "k", "v1")
        storage.set_meta(conn, "k", "v2")
    with closing(storage.connect(db)) as conn:
        assert storage.get_meta(conn, "k") == "v2"
        assert storage.get_meta(conn, "missing") is None


def test_database_from_newer_netwatch_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "nw.db"
    with closing(sqlite3.connect(db)) as raw:
        raw.execute("PRAGMA user_version = 99")
    with pytest.raises(StorageError, match="newer than this Netwatch"):
        storage.connect(db)


def test_unopenable_path_is_a_storage_error(tmp_path: Path) -> None:
    with pytest.raises(StorageError, match="cannot open database"):
        storage.connect(tmp_path / "no-such-dir" / "nw.db")


def test_failed_transaction_is_rolled_back(tmp_path: Path) -> None:
    with closing(storage.connect(tmp_path / "nw.db")) as conn:
        with pytest.raises(RuntimeError), storage.transaction(conn):
            conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')")
            raise RuntimeError("boom")
        assert storage.get_meta(conn, "k") is None


def test_upgrade_from_an_older_schema_keeps_existing_rows(tmp_path: Path) -> None:
    # A database written by v0.2.0 (schema 2), as on the VM, must upgrade in place.
    db = tmp_path / "nw.db"
    with closing(sqlite3.connect(db)) as raw:
        for version in (1, 2):
            for statement in storage.MIGRATIONS[version]:
                raw.execute(statement)
        raw.execute(
            "INSERT INTO dns_queries (ts_us, serial, client, name, qtype, status)"
            " VALUES (1, 1, '192.0.2.10', 'example.com', 'A', 'forwarded')"
        )
        raw.execute("PRAGMA user_version = 2")
        raw.commit()
    with closing(storage.connect(db)) as conn:
        assert storage.schema_version(conn) == storage.SCHEMA_VERSION
        assert conn.execute("SELECT count(*) FROM dns_queries").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM auth_events").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 0


def test_upgrade_from_v0_3_0_keeps_alerts(tmp_path: Path) -> None:
    # v0.3.0 (schema 3) is what the VM runs before Phase 3.
    db = tmp_path / "nw.db"
    with closing(sqlite3.connect(db)) as raw:
        for version in (1, 2, 3):
            for statement in storage.MIGRATIONS[version]:
                raw.execute(statement)
        raw.execute(
            "INSERT INTO alerts (ts_us, kind, severity, subject, message)"
            " VALUES (1, 'ssh-brute-force', 'warning', '203.0.113.5', 'm')"
        )
        raw.execute("PRAGMA user_version = 3")
        raw.commit()
    with closing(storage.connect(db)) as conn:
        assert storage.schema_version(conn) == 4
        assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM device_addresses").fetchone()[0] == 0
