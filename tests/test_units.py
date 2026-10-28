"""Checks on the systemd unit files that unit tests can make without systemd."""

from __future__ import annotations

from pathlib import Path

UNITS = Path(__file__).resolve().parent.parent / "deploy" / "systemd"


def _settings(unit: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in (UNITS / unit).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith(("#", ";")):
            key, _, value = line.partition("=")
            values.setdefault(key.strip(), []).append(value.strip())
    return values


def test_dns_logger_can_read_the_boot_id() -> None:
    # Regression: with ProcSubset=pid, /proc/sys is hidden and journalctl fails at start with
    # "Failed to get boot ID: No such file or directory", so netwatch-dns never ran on the VM.
    assert "ProcSubset" not in _settings("netwatch-dns.service")


def test_dns_logger_is_in_the_journal_group_and_offline() -> None:
    settings = _settings("netwatch-dns.service")
    assert settings["SupplementaryGroups"] == ["systemd-journal"]
    assert settings["PrivateNetwork"] == ["yes"]
    assert settings["User"] == ["netwatch"]


def test_every_service_runs_as_netwatch_without_capabilities() -> None:
    for unit in UNITS.glob("netwatch-*.service"):
        settings = _settings(unit.name)
        assert settings["User"] == ["netwatch"], unit.name
        assert settings["CapabilityBoundingSet"] == [""], unit.name
        assert settings["NoNewPrivileges"] == ["yes"], unit.name
