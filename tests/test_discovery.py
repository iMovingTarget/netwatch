from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from netwatch import alerts, devicedb, discovery, storage
from netwatch.alerts import Alert
from netwatch.discovery import KIND_NEW_DEVICE
from netwatch.oui import VendorLookup
from netwatch.scanner import Sighting

REGISTRY = Path(__file__).parent / "fixtures" / "ieee-data"
ROUTER = Sighting("192.0.2.1", "00:00:5e:00:53:01")
LAPTOP = Sighting("192.0.2.10", "00:00:5e:00:53:0a")
PHONE = Sighting("192.0.2.97", "02:00:5e:00:53:63")  # private Wi-Fi address
SENSOR = Sighting("192.0.2.40", "70:b3:d5:1a:b0:01")
MINUTE_US = 60_000_000


class CountingLookup(VendorLookup):
    def __init__(self) -> None:
        super().__init__(REGISTRY)
        self.asked: list[str] = []

    def vendor(self, mac: str) -> str | None:
        self.asked.append(mac)
        return super().vendor(mac)


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / "nw.db")) as c:
        yield c


@pytest.fixture
def vendors() -> CountingLookup:
    return CountingLookup()


def test_first_scan_is_the_baseline_and_raises_nothing(
    conn: sqlite3.Connection, vendors: CountingLookup
) -> None:
    result = discovery.record_scan(conn, [ROUTER, LAPTOP], 0, vendors)
    assert result == discovery.ScanResult(devices=2, new=2, alerts=(), baseline=True)
    assert [(d.mac, d.known, d.vendor) for d in devicedb.devices(conn)] == [
        (ROUTER.mac, True, "ICANN, IANA Department"),
        (LAPTOP.mac, True, "ICANN, IANA Department"),
    ]
    assert storage.get_meta(conn, discovery.BASELINE_KEY) == "0"
    assert alerts.recent(conn, 10) == []


def test_a_device_after_the_baseline_raises_one_alert(
    conn: sqlite3.Connection, vendors: CountingLookup
) -> None:
    discovery.record_scan(conn, [ROUTER, LAPTOP], 0, vendors)
    result = discovery.record_scan(conn, [ROUTER, LAPTOP, SENSOR], 5 * MINUTE_US, vendors)
    assert result.alerts == (
        Alert(
            5 * MINUTE_US,
            KIND_NEW_DEVICE,
            "warning",
            SENSOR.mac,
            "new device 70:b3:d5:1a:b0:01 at 192.0.2.40 (Example Sensors Ltd)",
        ),
    )
    [stored] = alerts.recent(conn, 10)
    assert (stored.kind, stored.subject) == (KIND_NEW_DEVICE, SENSOR.mac)
    assert [d.mac for d in devicedb.devices(conn, unknown_only=True)] == [SENSOR.mac]

    # Still there five minutes later: it's the same device, not a new one.
    again = discovery.record_scan(conn, [ROUTER, LAPTOP, SENSOR], 10 * MINUTE_US, vendors)
    assert (again.new, again.alerts) == (0, ())
    assert len(alerts.recent(conn, 10)) == 1


def test_a_known_device_returning_is_not_new(
    conn: sqlite3.Connection, vendors: CountingLookup
) -> None:
    discovery.record_scan(conn, [ROUTER, LAPTOP], 0, vendors)
    discovery.record_scan(conn, [ROUTER], 5 * MINUTE_US, vendors)  # laptop asleep
    result = discovery.record_scan(conn, [ROUTER, LAPTOP], 10 * MINUTE_US, vendors)
    assert result.alerts == ()


def test_a_phone_with_a_new_private_address_is_a_new_device(
    conn: sqlite3.Connection, vendors: CountingLookup
) -> None:
    discovery.record_scan(conn, [ROUTER, PHONE], 0, vendors)
    new_mac = Sighting("192.0.2.100", "da:00:5e:00:53:64")
    result = discovery.record_scan(conn, [ROUTER, new_mac], 5 * MINUTE_US, vendors)
    [alert] = result.alerts
    assert alert.message == (
        "new device da:00:5e:00:53:64 at 192.0.2.100 (locally administered address, so no"
        " vendor; phones use these as private Wi-Fi addresses)"
    )
    device = devicedb.get(conn, new_mac.mac)
    assert device is not None
    assert (device.local_admin, device.vendor) == (True, None)


def test_unregistered_vendor_is_said_so(conn: sqlite3.Connection, vendors: CountingLookup) -> None:
    discovery.record_scan(conn, [ROUTER], 0, vendors)
    stranger = Sighting("192.0.2.66", "00:00:5d:00:00:01")
    [alert] = discovery.record_scan(conn, [stranger], 1, vendors).alerts
    assert alert.message.endswith("(vendor not in the IEEE registry)")


def test_an_empty_scan_is_not_a_baseline(conn: sqlite3.Connection, vendors: CountingLookup) -> None:
    # Not even the router answered: the scan didn't work, so it can't say what belongs here.
    empty = discovery.record_scan(conn, [], 0, vendors)
    assert (empty.devices, empty.baseline) == (0, False)
    assert storage.get_meta(conn, discovery.BASELINE_KEY) is None
    assert storage.get_meta(conn, discovery.LAST_SCAN_KEY) == "0"
    assert discovery.record_scan(conn, [ROUTER, LAPTOP], 1, vendors).baseline
    assert alerts.recent(conn, 10) == []


def test_a_mac_answering_for_two_addresses_is_one_device(
    conn: sqlite3.Connection, vendors: CountingLookup
) -> None:
    discovery.record_scan(conn, [ROUTER], 0, vendors)
    twice = [Sighting("192.0.2.40", SENSOR.mac), Sighting("192.0.2.41", SENSOR.mac)]
    result = discovery.record_scan(conn, [*twice, twice[0]], 1, vendors)
    assert (result.devices, result.new, len(result.alerts)) == (1, 1, 1)
    assert [a.ip for a in devicedb.addresses(conn, SENSOR.mac)] == ["192.0.2.40", "192.0.2.41"]
    assert storage.get_meta(conn, discovery.LAST_FOUND_KEY) == "1"


def test_a_device_that_moves_keeps_its_history(
    conn: sqlite3.Connection, vendors: CountingLookup
) -> None:
    discovery.record_scan(conn, [ROUTER, PHONE], 0, vendors)
    moved = Sighting("192.0.2.100", PHONE.mac)
    assert discovery.record_scan(conn, [ROUTER, moved], 1, vendors).alerts == ()
    assert [a.ip for a in devicedb.addresses(conn, PHONE.mac)] == ["192.0.2.97", "192.0.2.100"]


def test_vendors_are_looked_up_only_for_new_devices(
    conn: sqlite3.Connection, vendors: CountingLookup
) -> None:
    discovery.record_scan(conn, [ROUTER, LAPTOP], 0, vendors)
    discovery.record_scan(conn, [ROUTER, LAPTOP, SENSOR], 1, vendors)
    assert vendors.asked == [ROUTER.mac, LAPTOP.mac, SENSOR.mac]


def test_prune_keeps_devices_and_other_detectors_alerts(
    conn: sqlite3.Connection, vendors: CountingLookup
) -> None:
    discovery.record_scan(conn, [ROUTER], 0, vendors)
    discovery.record_scan(conn, [ROUTER, SENSOR], 10, vendors)
    with storage.transaction(conn):
        alerts.store(conn, [Alert(10, "ssh-brute-force", "warning", "203.0.113.5", "m")])
    discovery.record_scan(conn, [ROUTER], 100, vendors)
    assert discovery.prune(conn, 50) == 2  # the sensor's address stretch and its alert
    assert [a.kind for a in alerts.recent(conn, 10)] == ["ssh-brute-force"]
    assert len(devicedb.devices(conn)) == 2
