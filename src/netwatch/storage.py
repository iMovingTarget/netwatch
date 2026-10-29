"""SQLite storage shared by the Netwatch services.

One database file in the state directory. The services write to it and the CLI and dashboard read
from it, so it runs in WAL mode: readers never block the writer and the writer never blocks
readers. A busy timeout makes a second writer wait for the lock instead of failing at once.

The schema version lives in SQLite's ``user_version`` header field. Migrations run in order inside
one write transaction, so two services starting at the same moment can't both migrate.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from netwatch.errors import StorageError

BUSY_TIMEOUT_S = 5.0

# Version -> statements that move the schema from version - 1 to version. Append only.
MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: ("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",),
    2: (
        # One row per client DNS query. ts_us is when dnsmasq logged the query (microseconds
        # since the epoch, as the journal records it). The ingester may read the same journal
        # lines twice after a restart; UNIQUE (ts_us, serial) makes storing them idempotent.
        """CREATE TABLE dns_queries (
            id INTEGER PRIMARY KEY,
            ts_us INTEGER NOT NULL,
            serial INTEGER NOT NULL,
            client TEXT NOT NULL,
            name TEXT NOT NULL,
            qtype TEXT NOT NULL,
            status TEXT NOT NULL,
            answer TEXT,
            upstream TEXT,
            UNIQUE (ts_us, serial)
        )""",
        "CREATE INDEX dns_queries_status_ts ON dns_queries (status, ts_us)",
        "CREATE INDEX dns_queries_client_ts ON dns_queries (client, ts_us)",
    ),
    3: (
        # One row per failed or successful SSH login. cursor is the journal entry's cursor,
        # unique per entry, so storing the same entry twice is a no-op.
        """CREATE TABLE auth_events (
            id INTEGER PRIMARY KEY,
            ts_us INTEGER NOT NULL,
            source TEXT NOT NULL,
            username TEXT NOT NULL,
            outcome TEXT NOT NULL,
            method TEXT,
            invalid_user INTEGER NOT NULL,
            message TEXT NOT NULL,
            cursor TEXT NOT NULL UNIQUE
        )""",
        "CREATE INDEX auth_events_ts ON auth_events (ts_us)",
        "CREATE INDEX auth_events_source_ts ON auth_events (source, ts_us)",
        # Alerts from every detector. subject is what an alert is about (an address, a
        # device). notified_us is set by the alerting service once it has sent the alert.
        """CREATE TABLE alerts (
            id INTEGER PRIMARY KEY,
            ts_us INTEGER NOT NULL,
            kind TEXT NOT NULL,
            severity TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            notified_us INTEGER
        )""",
        "CREATE INDEX alerts_ts ON alerts (ts_us)",
        "CREATE INDEX alerts_kind_ts ON alerts (kind, ts_us)",
    ),
    4: (
        # One row per MAC address ever seen on the LAN by the ARP scan. Rows are kept forever:
        # deleting one would make a returning device look new. known is 1 for devices in the
        # first (baseline) scan and devices the user labelled; a device first seen later is
        # unknown until labelled. local_admin marks a locally administered address (such as a
        # phone's private Wi-Fi address), which has no vendor.
        """CREATE TABLE devices (
            mac TEXT PRIMARY KEY,
            vendor TEXT,
            local_admin INTEGER NOT NULL,
            label TEXT,
            known INTEGER NOT NULL,
            first_seen_us INTEGER NOT NULL,
            last_seen_us INTEGER NOT NULL,
            last_ip TEXT NOT NULL
        )""",
        # Which device held which address, and when: one row per stretch at one address,
        # ended when another device takes the address, so a DNS query (stored by client
        # address) can be traced to a device.
        """CREATE TABLE device_addresses (
            id INTEGER PRIMARY KEY,
            mac TEXT NOT NULL REFERENCES devices (mac),
            ip TEXT NOT NULL,
            first_seen_us INTEGER NOT NULL,
            last_seen_us INTEGER NOT NULL
        )""",
        "CREATE INDEX device_addresses_mac ON device_addresses (mac, last_seen_us)",
        "CREATE INDEX device_addresses_ip ON device_addresses (ip, last_seen_us)",
    ),
}
SCHEMA_VERSION = max(MIGRATIONS)


def connect(path: Path) -> sqlite3.Connection:
    """Open the database at ``path`` and bring its schema up to date.

    The connection is in autocommit mode; group writes with ``transaction()``.
    """
    try:
        conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_S, isolation_level=None)
    except sqlite3.Error as exc:
        raise StorageError(f"cannot open database {path}: {exc}") from exc
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA foreign_keys = ON")
        _migrate(conn)
    except sqlite3.Error as exc:
        conn.close()
        raise StorageError(f"cannot open database {path}: {exc}") from exc
    except BaseException:
        conn.close()
        raise
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block as one write transaction: committed on success, rolled back on error.

    BEGIN IMMEDIATE takes the write lock at the start. A deferred transaction that reads first
    and writes later can fail with "database is locked" when another writer got in between;
    taking the lock up front turns that into a wait covered by the busy timeout.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def schema_version(conn: sqlite3.Connection) -> int:
    version: int = conn.execute("PRAGMA user_version").fetchone()[0]
    return version


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    with transaction(conn):
        put_meta(conn, key, value)


def put_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Like set_meta, but inside a transaction the caller already holds."""
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)"
        " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row[0])


def _migrate(conn: sqlite3.Connection) -> None:
    with transaction(conn):
        current = schema_version(conn)
        if current > SCHEMA_VERSION:
            raise StorageError(
                f"database schema version {current} is newer than this Netwatch supports"
                f" ({SCHEMA_VERSION}); install a newer Netwatch"
            )
        for version in range(current + 1, SCHEMA_VERSION + 1):
            for statement in MIGRATIONS[version]:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {version:d}")
