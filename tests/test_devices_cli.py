"""The `netwatch devices` commands and the netwatch-discovery service's scan, without a LAN."""

from __future__ import annotations

import json
import logging
from contextlib import closing
from dataclasses import replace
from datetime import UTC
from ipaddress import IPv4Interface
from pathlib import Path

import pytest

from netwatch import alerts, devicedb, discovery, report, storage
from netwatch.__main__ import main
from netwatch.config import load_settings
from netwatch.devicedb import Device
from netwatch.errors import ConfigError, NetwatchError
from netwatch.ingest import DB_NAME
from netwatch.scanner import LocalInterface, ScanReport, Sighting

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "arp-scans.jsonl"
REGISTRY = ROOT / "tests" / "fixtures" / "ieee-data"
T0 = 1_793_293_200_000_000  # 2026-10-29 17:00:00 UTC in microseconds
LOCAL = LocalInterface("eth0", "00:00:5e:00:53:35", IPv4Interface("192.0.2.53/24"))


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {"NETWATCH_STATE_DIR": str(tmp_path), "NETWATCH_OUI_DIR": str(REGISTRY)}


def test_example_scans_give_a_baseline_and_two_alerts(
    env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["devices", "scan", "--from-file", str(EXAMPLE)], environ=env) == 0
    assert capsys.readouterr().out == f"recorded 4 scans from {EXAMPLE}, 2 new-device alerts\n"
    assert main(["devices"], environ=env) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].endswith(": 4 of 5 devices answered")
    assert len(out) == 2 + 5
    assert main(["devices", "--unknown"], environ=env) == 0
    unknown = capsys.readouterr().out.splitlines()
    assert [line.split()[0] for line in unknown[2:]] == ["192.0.2.100", "192.0.2.120"]
    assert "answered" not in unknown[0]  # a count of a partial list would mislead


def test_importing_the_same_scans_again_raises_nothing_new(
    env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    main(["devices", "scan", "--from-file", str(EXAMPLE)], environ=env)
    assert main(["devices", "scan", "--from-file", str(EXAMPLE)], environ=env) == 0
    assert capsys.readouterr().out.endswith(
        "4 scans from " + str(EXAMPLE) + ", 0 new-device alerts\n"
    )


def test_labelling_marks_a_device_known(
    env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    main(["devices", "scan", "--from-file", str(EXAMPLE)], environ=env)
    capsys.readouterr()
    assert main(["devices", "label", "00-00-5E-00-53-64", "  phone  "], environ=env) == 0
    assert capsys.readouterr().out == "00:00:5e:00:53:64 is now known as 'phone'\n"
    with closing(storage.connect(Path(env["NETWATCH_STATE_DIR"]) / DB_NAME)) as conn:
        device = devicedb.get(conn, "00:00:5e:00:53:64")
    assert device is not None and (device.label, device.known) == ("phone", True)
    main(["devices", "label", "06:00:5e:00:53:78", "visitor"], environ=env)
    capsys.readouterr()
    assert main(["devices", "--unknown"], environ=env) == 0
    assert capsys.readouterr().out == "no unknown devices\n"


@pytest.mark.parametrize(
    ("args", "code", "message"),
    [
        (["00:00:5e:00:53:99", "tv"], 1, "no device with MAC address 00:00:5e:00:53:99"),
        (["tv", "00:00:5e:00:53:64"], 2, "'tv' is not a MAC address"),
        (["00:00:5e:00:53:64", ""], 2, "1 to 64 printable characters"),
        (["00:00:5e:00:53:64", "tv\x1b[2J"], 2, "1 to 64 printable characters"),
        (["00:00:5e:00:53:64", "x" * 65], 2, "1 to 64 printable characters"),
    ],
)
def test_bad_labels_are_refused(
    env: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    code: int,
    message: str,
) -> None:
    main(["devices", "scan", "--from-file", str(EXAMPLE)], environ=env)
    capsys.readouterr()
    assert main(["devices", "label", *args], environ=env) == code
    err = capsys.readouterr().err
    assert message in err and "Traceback" not in err


def test_scan_without_an_interface_is_a_config_error(
    env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["devices", "scan"], environ=env) == 2
    assert "NETWATCH_DISCOVERY_INTERFACE is not set" in capsys.readouterr().err


def test_service_scan_records_logs_and_alerts(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = load_settings(
        {
            "NETWATCH_STATE_DIR": str(tmp_path),
            "NETWATCH_OUI_DIR": str(REGISTRY),
            "NETWATCH_DISCOVERY_INTERFACE": "eth0",
        }
    )
    lan = [Sighting("192.0.2.1", "00:00:5e:00:53:01")]

    def fake_scan(name: str) -> ScanReport:
        assert name == "eth0"
        return ScanReport(LOCAL, 253, tuple(lan))

    clock = iter(range(T0, T0 + 100 * 300_000_000, 300_000_000))
    with caplog.at_level(logging.INFO, logger="netwatch"):
        assert discovery.run(settings, fake_scan, lambda: next(clock)).baseline
        lan.append(Sighting("192.0.2.66", "00:00:5e:00:53:66"))
        result = discovery.run(settings, fake_scan, lambda: next(clock))
        lan.clear()
        discovery.run(settings, fake_scan, lambda: next(clock))
    assert (result.devices, result.new) == (2, 1)
    messages = [r.getMessage() for r in caplog.records]
    assert messages == [
        "first scan of eth0 (192.0.2.0/24): 1 devices recorded as known (the baseline)",
        "scanned 253 addresses on eth0 (192.0.2.0/24): 2 devices, 1 new",
        "ALERT warning new-device: new device 00:00:5e:00:53:66 at 192.0.2.66"
        " (ICANN, IANA Department)",
        "no device answered on eth0 (192.0.2.0/24), not even the router",
    ]
    with closing(storage.connect(tmp_path / DB_NAME)) as conn:
        assert [a.subject for a in alerts.recent(conn, 10)] == ["00:00:5e:00:53:66"]


def test_service_prunes_old_history(tmp_path: Path) -> None:
    settings = load_settings(
        {
            "NETWATCH_STATE_DIR": str(tmp_path),
            "NETWATCH_OUI_DIR": str(REGISTRY),
            "NETWATCH_DISCOVERY_INTERFACE": "eth0",
            "NETWATCH_DISCOVERY_RETENTION_DAYS": "1",
        }
    )
    day_us = 86_400_000_000
    sightings = (Sighting("192.0.2.1", "00:00:5e:00:53:01"),)
    discovery.run(settings, lambda n: ScanReport(LOCAL, 253, sightings), lambda: T0)
    moved = (Sighting("192.0.2.2", "00:00:5e:00:53:01"),)
    discovery.run(settings, lambda n: ScanReport(LOCAL, 253, moved), lambda: T0 + 2 * day_us)
    with closing(storage.connect(tmp_path / DB_NAME)) as conn:
        assert [a.ip for a in devicedb.addresses(conn, "00:00:5e:00:53:01")] == ["192.0.2.2"]
        assert len(devicedb.devices(conn)) == 1


@pytest.mark.parametrize(
    "line",
    [
        "not json",
        '{"devices": []}',
        '{"time": "2026-10-29T17:00:00", "devices": []}',  # no UTC offset
        '{"time": "2026-10-29T17:00:00+00:00", "devices": [["192.0.2.1", "router"]]}',
        '{"time": "2026-10-29T17:00:00+00:00", "devices": [["2001:db8::1", "00:00:5e:00:53:01"]]}',
    ],
)
def test_malformed_saved_scans_name_the_line(tmp_path: Path, line: str) -> None:
    path = tmp_path / "scans.jsonl"
    good = json.dumps({"time": "2026-10-29T17:00:00+00:00", "devices": []})
    path.write_text(f"{good}\n\n{line}\n")
    with pytest.raises(NetwatchError, match=r"scans.jsonl, line 3: not a saved scan"):
        discovery.read_scans(path)


def test_missing_saved_scans_file(tmp_path: Path) -> None:
    with pytest.raises(NetwatchError, match="cannot read"):
        discovery.read_scans(tmp_path / "missing.jsonl")


def test_devices_table_is_aligned_and_escapes_names() -> None:
    base = Device(
        "00:00:5e:00:53:01",
        "ICANN, IANA Department",
        local_admin=False,
        label=None,
        known=True,
        first_seen_us=T0,
        last_seen_us=T0 + 600_000_000,
        last_ip="192.0.2.1",
    )
    table = report.devices_table(
        [
            replace(base, label="router\x1b[2J"),
            replace(
                base, mac="02:00:5e:00:53:61", last_ip="192.0.2.97", vendor=None, local_admin=True
            ),
            replace(
                base,
                mac="00:00:5d:00:00:01",
                last_ip="192.0.2.120",
                vendor=None,
                known=False,
                last_seen_us=T0,
            ),
        ],
        last_scan_us=T0 + 600_000_000,
        tz=UTC,
    )
    assert table.splitlines() == [
        "last scan 2026-10-29 17:10:00: 2 of 3 devices answered",
        "IP           MAC                FIRST SEEN           LAST SEEN            STATUS  NAME",
        "192.0.2.1    00:00:5e:00:53:01  2026-10-29 17:00:00  2026-10-29 17:10:00  known   "
        "router\\x1b[2J [ICANN, IANA Department]",
        "192.0.2.97   02:00:5e:00:53:61  2026-10-29 17:00:00  2026-10-29 17:10:00  known   "
        "[locally administered]",
        "192.0.2.120  00:00:5d:00:00:01  2026-10-29 17:00:00  2026-10-29 17:00:00  new     "
        "[vendor unknown]",
    ]
    assert report.devices_table([], None) == "no devices recorded yet\n"


def test_config_error_is_raised_before_scanning(tmp_path: Path) -> None:
    settings = load_settings({"NETWATCH_STATE_DIR": str(tmp_path)})
    with pytest.raises(ConfigError):
        discovery.run(settings, lambda n: pytest.fail("scanned without an interface"))
