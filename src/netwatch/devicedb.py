"""Store and query the LAN device inventory in the Netwatch database."""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from typing import Any

_COLUMNS = "mac, vendor, local_admin, label, known, first_seen_us, last_seen_us, last_ip"


@dataclass(frozen=True)
class Device:
    mac: str  # lower-case aa:bb:cc:dd:ee:ff
    vendor: str | None  # from the IEEE registry when first seen; None if unknown
    local_admin: bool  # locally administered address, e.g. a phone's private Wi-Fi address
    label: str | None  # a name the user gave it
    known: bool  # in the baseline scan, or labelled
    first_seen_us: int
    last_seen_us: int
    last_ip: str


@dataclass(frozen=True)
class AddressStretch:
    """An unbroken stretch of time a device answered for one address."""

    ip: str
    first_seen_us: int
    last_seen_us: int


def _device(row: tuple[Any, ...]) -> Device:
    mac, vendor, local_admin, label, known, first, last, ip = row
    return Device(mac, vendor, bool(local_admin), label, bool(known), first, last, ip)


def get(conn: sqlite3.Connection, mac: str) -> Device | None:
    row = conn.execute(f"SELECT {_COLUMNS} FROM devices WHERE mac = ?", (mac,)).fetchone()
    return None if row is None else _device(row)


def add(
    conn: sqlite3.Connection,
    mac: str,
    ip: str,
    ts_us: int,
    vendor: str | None,
    local_admin: bool,
    known: bool,
) -> None:
    """Record a device seen for the first time. Call inside storage.transaction()."""
    conn.execute(
        f"INSERT INTO devices ({_COLUMNS}) VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
        (mac, vendor, int(local_admin), int(known), ts_us, ts_us, ip),
    )
    conn.execute(
        "INSERT INTO device_addresses (mac, ip, first_seen_us, last_seen_us) VALUES (?, ?, ?, ?)",
        (mac, ip, ts_us, ts_us),
    )


def seen(conn: sqlite3.Connection, mac: str, ip: str, ts_us: int) -> None:
    """Record that a known MAC answered for ``ip`` at ``ts_us``. Call inside a transaction.

    A device keeps one stretch per address until another device is seen at that address: a
    phone that moves to a new lease and back, or a range extender that answers for several
    addresses, extends its stretches instead of adding a row per scan. Once another MAC has
    held the address, the next sighting starts a new stretch, so device_at() stays right.
    """
    conn.execute(
        "UPDATE devices SET last_seen_us = max(last_seen_us, ?), last_ip = ? WHERE mac = ?",
        (ts_us, ip, mac),
    )
    latest = conn.execute(
        "SELECT id, last_seen_us FROM device_addresses WHERE mac = ? AND ip = ?"
        " ORDER BY last_seen_us DESC, id DESC LIMIT 1",
        (mac, ip),
    ).fetchone()
    taken_since = (
        latest is not None
        and conn.execute(
            "SELECT 1 FROM device_addresses WHERE ip = ? AND mac != ? AND last_seen_us > ? LIMIT 1",
            (ip, mac, latest[1]),
        ).fetchone()
    )
    if latest is not None and not taken_since:
        conn.execute(
            "UPDATE device_addresses SET last_seen_us = max(last_seen_us, ?) WHERE id = ?",
            (ts_us, latest[0]),
        )
    else:
        conn.execute(
            "INSERT INTO device_addresses (mac, ip, first_seen_us, last_seen_us)"
            " VALUES (?, ?, ?, ?)",
            (mac, ip, ts_us, ts_us),
        )


def devices(conn: sqlite3.Connection, unknown_only: bool = False) -> list[Device]:
    """Every device, by address (192.0.2.2 before 192.0.2.10)."""
    where = "WHERE known = 0" if unknown_only else ""
    rows = conn.execute(f"SELECT {_COLUMNS} FROM devices {where}").fetchall()
    found = [_device(row) for row in rows]
    return sorted(found, key=lambda d: (ipaddress.ip_address(d.last_ip), d.mac))


def set_label(conn: sqlite3.Connection, mac: str, label: str) -> bool:
    """Name a device and mark it known. Returns False if there is no such device."""
    cursor = conn.execute("UPDATE devices SET label = ?, known = 1 WHERE mac = ?", (label, mac))
    return cursor.rowcount == 1


def addresses(conn: sqlite3.Connection, mac: str) -> list[AddressStretch]:
    """The addresses a device has held, oldest first."""
    rows = conn.execute(
        "SELECT ip, first_seen_us, last_seen_us FROM device_addresses WHERE mac = ?"
        " ORDER BY first_seen_us, id",
        (mac,),
    )
    return [AddressStretch(*row) for row in rows]


def device_at(conn: sqlite3.Connection, ip: str, ts_us: int) -> str | None:
    """The MAC of the device that held ``ip`` at ``ts_us`` as far as the scans saw, or None.

    Between two scans an address is attributed to the device the earlier scan found there.
    """
    row = conn.execute(
        "SELECT mac FROM device_addresses WHERE ip = ? AND first_seen_us <= ?"
        " ORDER BY last_seen_us DESC, id DESC LIMIT 1",
        (ip, ts_us),
    ).fetchone()
    return None if row is None else str(row[0])


def prune_addresses(conn: sqlite3.Connection, older_than_us: int) -> int:
    """Delete address stretches that ended before ``older_than_us``. Devices are kept."""
    return conn.execute(
        "DELETE FROM device_addresses WHERE last_seen_us < ?", (older_than_us,)
    ).rowcount
