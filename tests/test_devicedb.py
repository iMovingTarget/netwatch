from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from netwatch import devicedb, storage
from netwatch.devicedb import AddressStretch

ROUTER = "00:00:5e:00:53:01"
LAPTOP = "00:00:5e:00:53:0a"
PHONE = "02:00:5e:00:53:63"  # locally administered: a private Wi-Fi address


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / "nw.db")) as c:
        yield c


def _add(conn: sqlite3.Connection, mac: str, ip: str, ts: int, known: bool = True) -> None:
    with storage.transaction(conn):
        devicedb.add(conn, mac, ip, ts, "ICANN, IANA Department", mac == PHONE, known)


def test_new_device_is_stored_with_its_first_address(conn: sqlite3.Connection) -> None:
    _add(conn, PHONE, "192.0.2.99", 10, known=False)
    assert devicedb.get(conn, PHONE) == devicedb.Device(
        PHONE, "ICANN, IANA Department", True, None, False, 10, 10, "192.0.2.99"
    )
    assert devicedb.addresses(conn, PHONE) == [AddressStretch("192.0.2.99", 10, 10)]
    assert devicedb.get(conn, ROUTER) is None


def test_seen_at_the_same_address_extends_the_stretch(conn: sqlite3.Connection) -> None:
    _add(conn, LAPTOP, "192.0.2.10", 10)
    with storage.transaction(conn):
        devicedb.seen(conn, LAPTOP, "192.0.2.10", 20)
        devicedb.seen(conn, LAPTOP, "192.0.2.10", 30)
    device = devicedb.get(conn, LAPTOP)
    assert device is not None
    assert (device.first_seen_us, device.last_seen_us) == (10, 30)
    assert devicedb.addresses(conn, LAPTOP) == [AddressStretch("192.0.2.10", 10, 30)]


def test_a_device_that_moves_and_returns_extends_its_stretches(conn: sqlite3.Connection) -> None:
    _add(conn, PHONE, "192.0.2.97", 10)
    with storage.transaction(conn):
        devicedb.seen(conn, PHONE, "192.0.2.100", 20)  # a new DHCP lease
        devicedb.seen(conn, PHONE, "192.0.2.97", 30)  # and back again; nobody else had it
    device = devicedb.get(conn, PHONE)
    assert device is not None and device.last_ip == "192.0.2.97"
    assert devicedb.addresses(conn, PHONE) == [
        AddressStretch("192.0.2.97", 10, 30),
        AddressStretch("192.0.2.100", 20, 20),
    ]


def test_a_device_answering_for_two_addresses_adds_no_rows_per_scan(
    conn: sqlite3.Connection,
) -> None:
    # A Wi-Fi range extender answers ARP for its clients with its own MAC address. Seeing it
    # at two addresses in every scan must not add a row per scan.
    _add(conn, LAPTOP, "192.0.2.40", 10)
    for ts in (10, 20, 30):
        with storage.transaction(conn):
            devicedb.seen(conn, LAPTOP, "192.0.2.40", ts)
            devicedb.seen(conn, LAPTOP, "192.0.2.41", ts)
    assert devicedb.addresses(conn, LAPTOP) == [
        AddressStretch("192.0.2.40", 10, 30),
        AddressStretch("192.0.2.41", 10, 30),
    ]


def test_an_address_taken_by_another_device_starts_a_new_stretch(
    conn: sqlite3.Connection,
) -> None:
    _add(conn, LAPTOP, "192.0.2.50", 10)
    _add(conn, PHONE, "192.0.2.50", 20)  # the laptop was away; the phone got its lease
    with storage.transaction(conn):
        devicedb.seen(conn, LAPTOP, "192.0.2.50", 30)  # and the laptop has it back
    assert devicedb.addresses(conn, LAPTOP) == [
        AddressStretch("192.0.2.50", 10, 10),
        AddressStretch("192.0.2.50", 30, 30),
    ]
    assert devicedb.device_at(conn, "192.0.2.50", 15) == LAPTOP
    assert devicedb.device_at(conn, "192.0.2.50", 25) == PHONE
    assert devicedb.device_at(conn, "192.0.2.50", 35) == LAPTOP


def test_address_history_tells_which_device_held_an_address(conn: sqlite3.Connection) -> None:
    _add(conn, LAPTOP, "192.0.2.50", 10)
    with storage.transaction(conn):
        devicedb.seen(conn, LAPTOP, "192.0.2.50", 20)
        devicedb.seen(conn, LAPTOP, "192.0.2.51", 30)
    _add(conn, PHONE, "192.0.2.50", 40)  # the address was reused by another device
    assert devicedb.device_at(conn, "192.0.2.50", 5) is None  # before any scan saw it
    assert devicedb.device_at(conn, "192.0.2.50", 15) == LAPTOP
    assert devicedb.device_at(conn, "192.0.2.50", 35) == LAPTOP  # last seen there by a scan
    assert devicedb.device_at(conn, "192.0.2.50", 45) == PHONE


def test_devices_are_listed_by_address_and_can_be_filtered(conn: sqlite3.Connection) -> None:
    _add(conn, LAPTOP, "192.0.2.10", 10)
    _add(conn, ROUTER, "192.0.2.1", 10)
    _add(conn, PHONE, "192.0.2.9", 20, known=False)
    assert [d.last_ip for d in devicedb.devices(conn)] == ["192.0.2.1", "192.0.2.9", "192.0.2.10"]
    assert [d.mac for d in devicedb.devices(conn, unknown_only=True)] == [PHONE]


def test_labelling_a_device_marks_it_known(conn: sqlite3.Connection) -> None:
    _add(conn, PHONE, "192.0.2.9", 20, known=False)
    with storage.transaction(conn):
        assert devicedb.set_label(conn, PHONE, "Sergei's phone")
        assert not devicedb.set_label(conn, ROUTER, "router")  # never seen
    device = devicedb.get(conn, PHONE)
    assert device is not None
    assert (device.label, device.known) == ("Sergei's phone", True)


def test_pruning_drops_old_address_history_but_keeps_devices(conn: sqlite3.Connection) -> None:
    _add(conn, PHONE, "192.0.2.97", 10)
    with storage.transaction(conn):
        devicedb.seen(conn, PHONE, "192.0.2.100", 50)
    with storage.transaction(conn):
        assert devicedb.prune_addresses(conn, 20) == 1
    assert devicedb.addresses(conn, PHONE) == [AddressStretch("192.0.2.100", 50, 50)]
    assert devicedb.get(conn, PHONE) is not None
