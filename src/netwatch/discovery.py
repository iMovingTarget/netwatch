"""LAN device discovery: record what an ARP scan found and alert on new devices.

Every scan updates the inventory: devices seen before get a new "last seen" (and a new address
stretch if they moved); devices never seen before are added with their vendor. The first scan
that finds anything is the baseline: what's on the network when discovery is switched on is
assumed to belong there, so those devices are recorded as known without alerts. After that,
every MAC address seen for the first time raises one ``new-device`` alert, at warning severity,
and stays "unknown" until it is labelled.

One alert per MAC address, ever: a known phone that leaves and comes back is not new. A phone
that switches to a different private Wi-Fi address *is* a new MAC address, so it raises an alert;
the message says the address is locally administered, the usual sign of exactly that.

The socket side of a scan is in netwatch.scanner; this module only needs its results, so the
rules are tested without root or a network.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass

from netwatch import alerts, devicedb, storage
from netwatch.alerts import SEVERITY_WARNING, Alert
from netwatch.arp import is_locally_administered
from netwatch.oui import VendorLookup
from netwatch.scanner import Sighting

KIND_NEW_DEVICE = "new-device"
ALERT_KINDS = (KIND_NEW_DEVICE,)
BASELINE_KEY = "discovery.baseline_us"
LAST_SCAN_KEY = "discovery.last_scan_us"
LAST_FOUND_KEY = "discovery.last_scan_devices"


@dataclass(frozen=True)
class ScanResult:
    devices: int  # distinct MAC addresses that answered
    new: int  # of those, seen for the first time
    alerts: tuple[Alert, ...]
    baseline: bool  # this scan was the baseline


def new_device_message(mac: str, ip: str, vendor: str | None) -> str:
    if is_locally_administered(mac):
        detail = (
            "locally administered address, so no vendor;"
            " phones use these as private Wi-Fi addresses"
        )
    elif vendor is None:
        detail = "vendor not in the IEEE registry"
    else:
        detail = vendor
    return f"new device {mac} at {ip} ({detail})"


def record_scan(
    conn: sqlite3.Connection,
    sightings: Iterable[Sighting],
    ts_us: int,
    vendors: VendorLookup,
) -> ScanResult:
    """Update the inventory with one scan's results and store any alerts, in one transaction."""
    ordered = sorted(set(sightings), key=lambda s: (ipaddress.ip_address(s.ip), s.mac))
    # Look vendors up before taking the write lock: the first lookup reads the registry files.
    unseen = {s.mac for s in ordered if devicedb.get(conn, s.mac) is None}
    vendor_of = {mac: vendors.vendor(mac) for mac in sorted(unseen)}
    raised: list[Alert] = []
    with storage.transaction(conn):
        is_baseline = storage.get_meta(conn, BASELINE_KEY) is None and bool(ordered)
        added = 0
        for sighting in ordered:
            if devicedb.get(conn, sighting.mac) is not None:
                devicedb.seen(conn, sighting.mac, sighting.ip, ts_us)
                continue
            vendor = vendor_of.get(sighting.mac)
            devicedb.add(
                conn,
                sighting.mac,
                sighting.ip,
                ts_us,
                vendor,
                is_locally_administered(sighting.mac),
                known=is_baseline,
            )
            added += 1
            if not is_baseline:
                raised.append(
                    Alert(
                        ts_us=ts_us,
                        kind=KIND_NEW_DEVICE,
                        severity=SEVERITY_WARNING,
                        subject=sighting.mac,
                        message=new_device_message(sighting.mac, sighting.ip, vendor),
                    )
                )
        alerts.store(conn, raised)
        if is_baseline:
            storage.put_meta(conn, BASELINE_KEY, str(ts_us))
        storage.put_meta(conn, LAST_SCAN_KEY, str(ts_us))
        storage.put_meta(conn, LAST_FOUND_KEY, str(len({s.mac for s in ordered})))
    return ScanResult(len({s.mac for s in ordered}), added, tuple(raised), is_baseline)


def prune(conn: sqlite3.Connection, older_than_us: int) -> int:
    """Delete address history and new-device alerts from before ``older_than_us``."""
    with storage.transaction(conn):
        deleted = devicedb.prune_addresses(conn, older_than_us)
        deleted += alerts.prune(conn, older_than_us, ALERT_KINDS)
    return deleted
