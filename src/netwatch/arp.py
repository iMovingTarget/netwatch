"""ARP frames and MAC addresses, as pure functions (no sockets, so they test anywhere).

ARP (RFC 826) maps an IPv4 address to the MAC address of the device that holds it on the local
link. A device that doesn't answer ARP can't receive IPv4 traffic on the LAN at all, which is why
asking every address in the subnet "who has 192.0.2.N?" finds devices whether or not they
want to be found, unlike listening for traffic they choose to send.

An Ethernet frame carrying an ARP request for IPv4 is 42 bytes:

    Ethernet: destination MAC (6), source MAC (6), EtherType 0x0806 (2)
    ARP:      hardware type 1 = Ethernet (2), protocol type 0x0800 = IPv4 (2),
              hardware size 6 (1), protocol size 4 (1), operation 1 = request, 2 = reply (2),
              sender MAC (6), sender IPv4 (4), target MAC (6), target IPv4 (4)

Requests go to the broadcast MAC with a zero target MAC, and are padded to 60 bytes, the minimum
Ethernet frame (without its checksum), since not every driver pads short frames itself.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address

ETH_P_ARP = 0x0806
ETH_P_IP = 0x0800
ARP_REQUEST = 1
ARP_REPLY = 2
BROADCAST = "ff:ff:ff:ff:ff:ff"
MIN_FRAME = 60

_ETHERNET = struct.Struct("!6s6sH")
_ARP = struct.Struct("!HHBBH6s4s6s4s")
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class ArpPacket:
    operation: int  # ARP_REQUEST or ARP_REPLY
    sender_mac: str
    sender_ip: IPv4Address
    target_mac: str
    target_ip: IPv4Address


def normalize_mac(text: str) -> str:
    """``text`` as lower-case aa:bb:cc:dd:ee:ff. Accepts ':' or '-' separators or none.

    Raises ValueError for anything that isn't 12 hex digits.
    """
    digits = text.strip().lower().replace(":", "").replace("-", "")
    if len(digits) != 12 or not set(digits) <= _HEX:
        raise ValueError(f"{text!r} is not a MAC address such as 00:00:5e:00:53:01")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(normalize_mac(mac).replace(":", ""))


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def is_locally_administered(mac: str) -> bool:
    """True if the U/L bit of the first octet is set: the address wasn't assigned by IEEE.

    Phones use such addresses for privacy (iOS "Private Wi-Fi Address", Android "randomized MAC"),
    and so do some routers and virtual interfaces. They have no vendor in the IEEE registry.
    """
    return bool(mac_bytes(mac)[0] & 0x02)


def is_unicast(mac: str) -> bool:
    """False for multicast and broadcast addresses (I/G bit set) and for all zeros."""
    raw = mac_bytes(mac)
    return not raw[0] & 0x01 and raw != bytes(6)


def request(sender_mac: str, sender_ip: IPv4Address, target_ip: IPv4Address) -> bytes:
    """A broadcast frame asking which device has ``target_ip``."""
    own = mac_bytes(sender_mac)
    frame = _ETHERNET.pack(mac_bytes(BROADCAST), own, ETH_P_ARP) + _ARP.pack(
        1, ETH_P_IP, 6, 4, ARP_REQUEST, own, sender_ip.packed, bytes(6), target_ip.packed
    )
    return frame.ljust(MIN_FRAME, b"\0")


def reply(
    sender_mac: str, sender_ip: IPv4Address, target_mac: str, target_ip: IPv4Address
) -> bytes:
    """The frame a device sends back: "``sender_ip`` is at ``sender_mac``". Used by the tests."""
    frame = _ETHERNET.pack(mac_bytes(target_mac), mac_bytes(sender_mac), ETH_P_ARP) + _ARP.pack(
        1,
        ETH_P_IP,
        6,
        4,
        ARP_REPLY,
        mac_bytes(sender_mac),
        sender_ip.packed,
        mac_bytes(target_mac),
        target_ip.packed,
    )
    return frame.ljust(MIN_FRAME, b"\0")


def parse(frame: bytes) -> ArpPacket | None:
    """The ARP packet in an Ethernet frame, or None if it isn't Ethernet/IPv4 ARP."""
    if len(frame) < _ETHERNET.size + _ARP.size:
        return None
    _, _, ethertype = _ETHERNET.unpack_from(frame)
    if ethertype != ETH_P_ARP:
        return None
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = _ARP.unpack_from(frame, _ETHERNET.size)
    if (htype, ptype, hlen, plen) != (1, ETH_P_IP, 6, 4) or op not in (ARP_REQUEST, ARP_REPLY):
        return None
    return ArpPacket(op, format_mac(sha), IPv4Address(spa), format_mac(tha), IPv4Address(tpa))
