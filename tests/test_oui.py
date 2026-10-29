from __future__ import annotations

import logging
from pathlib import Path

import pytest

from netwatch.oui import VendorLookup, parse_registry

# The IEEE registry's file format, with a few entries (see fixtures/README.md).
REGISTRY = Path(__file__).parent / "fixtures" / "ieee-data"


@pytest.fixture
def lookup() -> VendorLookup:
    return VendorLookup(REGISTRY)


def test_fixture_keeps_the_registrys_crlf_line_endings() -> None:
    assert b"\r\n" in (REGISTRY / "oui.txt").read_bytes()


def test_vendor_by_oui(lookup: VendorLookup) -> None:
    # RFC 7042's documentation MACs are in IANA's OUI.
    assert lookup.vendor("00:00:5e:00:53:2a") == "ICANN, IANA Department"
    assert lookup.vendor("00-00-5F-00-00-01") == "Exämple Ünicode GmbH"


def test_longest_registered_prefix_wins(lookup: VendorLookup) -> None:
    # 70-B3-D5 is an IEEE block resold as smaller MA-M and MA-S blocks.
    assert lookup.vendor("70:b3:d5:1a:b0:01") == "Example Sensors Ltd"  # MA-S 70-B3-D5-1AB
    assert lookup.vendor("70:b3:d5:12:34:56") == "Example Meters Ltd"  # MA-M 70-B3-D5-1
    assert lookup.vendor("70:b3:d5:f0:00:01") == "IEEE Registration Authority"  # MA-L only


def test_unregistered_and_locally_administered_addresses_have_no_vendor(
    lookup: VendorLookup,
) -> None:
    assert lookup.vendor("00:00:5d:00:00:01") is None
    # The private Wi-Fi address of a phone: the locally administered bit is set (0x02).
    assert lookup.vendor("02:00:5e:00:53:2a") is None


def test_malformed_entries_are_skipped() -> None:
    text = (REGISTRY / "oui.txt").read_text(encoding="utf-8") + (REGISTRY / "mam.txt").read_text(
        encoding="utf-8"
    )
    prefixes = parse_registry(text)
    assert "0Z0000" not in prefixes
    assert "Malformed Range Ltd" not in prefixes.values()
    assert prefixes["70B3D51"] == "Example Meters Ltd"


def test_missing_registry_warns_once_and_finds_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    lookup = VendorLookup(tmp_path)
    with caplog.at_level(logging.WARNING, logger="netwatch"):
        assert lookup.vendor("00:00:5e:00:53:2a") is None
        assert lookup.vendor("00:00:5e:00:53:2b") is None
    assert [r.getMessage() for r in caplog.records] == [
        f"no IEEE registry in {tmp_path} (package ieee-data), so vendors are not shown"
    ]


def test_registry_is_read_only_when_a_vendor_is_needed(tmp_path: Path) -> None:
    lookup = VendorLookup(tmp_path)  # empty for now
    (tmp_path / "oui.txt").write_bytes((REGISTRY / "oui.txt").read_bytes())
    assert lookup.vendor("00:00:5e:00:53:2a") == "ICANN, IANA Department"
