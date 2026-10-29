"""Checks on the systemd unit files that unit tests can make without systemd."""

from __future__ import annotations

from pathlib import Path

import pytest

UNITS = Path(__file__).resolve().parent.parent / "deploy" / "systemd"


def _settings(unit: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in (UNITS / unit).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith(("#", ";")):
            key, _, value = line.partition("=")
            values.setdefault(key.strip(), []).append(value.strip())
    return values


# Services that run journalctl to follow a log.
JOURNAL_READERS = ("netwatch-dns.service", "netwatch-auth.service")


@pytest.mark.parametrize("unit", JOURNAL_READERS)
def test_journal_readers_can_read_the_boot_id(unit: str) -> None:
    # Regression: with ProcSubset=pid, /proc/sys is hidden and journalctl fails at start with
    # "Failed to get boot ID: No such file or directory", so netwatch-dns never ran on the VM.
    assert "ProcSubset" not in _settings(unit)


@pytest.mark.parametrize("unit", JOURNAL_READERS)
def test_journal_readers_are_in_the_journal_group_and_offline(unit: str) -> None:
    settings = _settings(unit)
    assert settings["SupplementaryGroups"] == ["systemd-journal"]
    assert settings["PrivateNetwork"] == ["yes"]
    assert settings["User"] == ["netwatch"]


# The only capability any service gets.
CAPABILITIES = {"netwatch-discovery.service": "CAP_NET_RAW"}


def test_every_service_runs_as_netwatch_with_only_the_capability_it_needs() -> None:
    units = sorted(UNITS.glob("netwatch-*.service"))
    assert len(units) == 4
    for unit in units:
        settings = _settings(unit.name)
        expected = CAPABILITIES.get(unit.name, "")
        assert settings["User"] == ["netwatch"], unit.name
        assert settings["CapabilityBoundingSet"] == [expected], unit.name
        assert settings["AmbientCapabilities"] == [expected], unit.name
        assert settings["NoNewPrivileges"] == ["yes"], unit.name


def test_scanner_reaches_the_lan_with_raw_frames_only() -> None:
    settings = _settings("netwatch-discovery.service")
    # PrivateNetwork would hide the LAN interface; PrivateUsers would void CAP_NET_RAW on it.
    assert "PrivateNetwork" not in settings
    assert "PrivateUsers" not in settings
    assert settings["RestrictAddressFamilies"] == ["AF_PACKET AF_INET AF_UNIX"]
    assert settings["IPAddressDeny"] == ["any"]
    assert "IPAddressAllow" not in settings


def test_scan_timer_runs_every_five_minutes() -> None:
    settings = _settings("netwatch-discovery.timer")
    assert settings["OnCalendar"] == ["*:0/5"]
    assert settings["WantedBy"] == ["timers.target"]
