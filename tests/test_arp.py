from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from netwatch import arp

# Documentation MAC addresses (RFC 7042) and IPv4 addresses (RFC 5737).
OWN_MAC = "00:00:5e:00:53:01"
OWN_IP = IPv4Address("192.0.2.53")
DEVICE_MAC = "00:00:5e:00:53:2a"
DEVICE_IP = IPv4Address("192.0.2.10")


def test_request_matches_rfc_826_byte_for_byte() -> None:
    expected = bytes.fromhex(
        "ffffffffffff"  # to: broadcast
        "00005e005301"  # from: us
        "0806"  # EtherType: ARP
        "0001"  # hardware type: Ethernet
        "0800"  # protocol type: IPv4
        "06"  # hardware address size
        "04"  # protocol address size
        "0001"  # operation: request
        "00005e005301"  # sender MAC: us
        "c0000235"  # sender IPv4: 192.0.2.53
        "000000000000"  # target MAC: unknown
        "c000020a"  # target IPv4: 192.0.2.10
    ) + bytes(18)  # padding to the 60-byte minimum frame
    assert arp.request(OWN_MAC, OWN_IP, DEVICE_IP) == expected


def test_reply_is_parsed() -> None:
    packet = arp.parse(arp.reply(DEVICE_MAC, DEVICE_IP, OWN_MAC, OWN_IP))
    assert packet == arp.ArpPacket(arp.ARP_REPLY, DEVICE_MAC, DEVICE_IP, OWN_MAC, OWN_IP)


def test_request_is_parsed_as_a_request() -> None:
    packet = arp.parse(arp.request(OWN_MAC, OWN_IP, DEVICE_IP))
    assert packet is not None
    assert (packet.operation, packet.target_ip, packet.target_mac) == (
        arp.ARP_REQUEST,
        DEVICE_IP,
        "00:00:00:00:00:00",
    )


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        arp.reply(DEVICE_MAC, DEVICE_IP, OWN_MAC, OWN_IP)[:41],  # truncated
        bytes.fromhex("ffffffffffff00005e0053010800") + bytes(46),  # IPv4, not ARP
        # ARP for another hardware type (6 = IEEE 802) and an unknown operation (9)
        arp.reply(DEVICE_MAC, DEVICE_IP, OWN_MAC, OWN_IP)[:14] + b"\x00\x06" + bytes(44),
        arp.reply(DEVICE_MAC, DEVICE_IP, OWN_MAC, OWN_IP)[:20] + b"\x00\x09" + bytes(38),
    ],
)
def test_other_frames_are_ignored(frame: bytes) -> None:
    assert arp.parse(frame) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("00:00:5E:00:53:2A", "00:00:5e:00:53:2a"),
        ("00-00-5e-00-53-2a", "00:00:5e:00:53:2a"),
        (" 00005e00532a ", "00:00:5e:00:53:2a"),
    ],
)
def test_mac_addresses_are_normalised(text: str, expected: str) -> None:
    assert arp.normalize_mac(text) == expected


@pytest.mark.parametrize("text", ["", "00:00:5e:00:53", "00:00:5e:00:53:2g", "router"])
def test_invalid_mac_addresses_are_refused(text: str) -> None:
    with pytest.raises(ValueError, match="not a MAC address"):
        arp.normalize_mac(text)


def test_locally_administered_addresses() -> None:
    assert not arp.is_locally_administered("00:00:5e:00:53:2a")  # assigned by IEEE
    # The second-lowest bit of the first octet: x2, x6, xa and xe in the first byte.
    for first in ("02", "06", "0a", "0e", "da", "42"):
        assert arp.is_locally_administered(f"{first}:00:5e:00:53:2a")


def test_unicast_addresses() -> None:
    assert arp.is_unicast(DEVICE_MAC)
    assert not arp.is_unicast(arp.BROADCAST)
    assert not arp.is_unicast("01:00:5e:00:00:fb")  # IPv4 multicast
    assert not arp.is_unicast("00:00:00:00:00:00")
