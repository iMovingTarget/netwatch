"""Sweep the local IPv4 subnet with ARP requests over a packet socket.

The sweep sends one ARP request per address in the interface's subnet (a /24 is 253 requests,
about 60 bytes each), then listens for replies addressed to this host. Devices that miss the first
pass (a phone in Wi-Fi power save wakes at the next beacon, or not at all) are asked again in a
second pass with a longer wait. A /24 takes about four seconds.

Sending raw Ethernet frames needs CAP_NET_RAW, the only capability netwatch-discovery.service
grants. The socket is bound to ARP frames on one interface and ignores this host's own outgoing
frames, so 253 copies of our requests can't crowd the replies out of its receive buffer.

The sweep itself works on a ``Link`` (send a frame, receive a frame), so it is tested with a
fake network: no root, no Linux needed.
"""

from __future__ import annotations

import contextlib
import errno
import select
import socket
import struct
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path
from types import TracebackType
from typing import Protocol

from netwatch import arp
from netwatch.errors import ScanError

MAX_ADDRESSES = 1024  # a /22: a home LAN is a /24; anything bigger is probably a mistake
SEND_GAP_S = 0.002  # between requests, so a burst doesn't swamp a Wi-Fi access point
PASS_WAITS_S = (1.0, 2.0)  # how long to listen after each pass

SYS_CLASS_NET = Path("/sys/class/net")
# Linux ioctl and socket option numbers (linux/sockios.h, linux/if_packet.h).
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
SOL_PACKET = 263
PACKET_IGNORE_OUTGOING = 23


@dataclass(frozen=True)
class Sighting:
    """A device answered an ARP request: ``ip`` is at ``mac``."""

    ip: str
    mac: str


@dataclass(frozen=True)
class LocalInterface:
    name: str
    mac: str
    address: IPv4Interface  # this host's address on the interface, with its network


@dataclass(frozen=True)
class ScanReport:
    interface: LocalInterface
    scanned: int  # addresses asked
    sightings: tuple[Sighting, ...]


class Link(Protocol):
    def send(self, frame: bytes) -> None: ...

    def recv(self, timeout: float) -> bytes | None:
        """The next frame within ``timeout`` seconds, or None."""
        ...


def targets(address: IPv4Interface) -> list[IPv4Address]:
    """Every host address in ``address``'s network except this host's own."""
    network = address.network
    if network.num_addresses > MAX_ADDRESSES:
        raise ScanError(
            f"{network} has {network.num_addresses} addresses; Netwatch scans at most"
            f" {MAX_ADDRESSES} (a /22)"
        )
    hosts = [host for host in network.hosts() if host != address.ip]
    if not hosts:
        raise ScanError(f"{network} has no other addresses to scan")
    return hosts


def sweep(
    link: Link,
    local: LocalInterface,
    addresses: Sequence[IPv4Address],
    waits: Sequence[float] = PASS_WAITS_S,
    gap: float = SEND_GAP_S,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Sighting]:
    """Ask every address in ``addresses``, one pass per entry in ``waits``; return who answered."""
    wanted = frozenset(addresses)
    found: dict[IPv4Address, set[str]] = {}
    for wait in waits:
        pending = [address for address in addresses if address not in found]
        if not pending:
            break
        for count, address in enumerate(pending, 1):
            link.send(arp.request(local.mac, local.address.ip, address))
            if gap:
                sleep(gap)
            if count % 32 == 0:  # read what has arrived so far, without waiting
                _receive(link, local, wanted, found, 0.0, monotonic)
        _receive(link, local, wanted, found, wait, monotonic)
    return sorted(
        (Sighting(str(ip), mac) for ip, macs in found.items() for mac in macs),
        key=lambda s: (IPv4Address(s.ip), s.mac),
    )


def _receive(
    link: Link,
    local: LocalInterface,
    wanted: frozenset[IPv4Address],
    found: dict[IPv4Address, set[str]],
    wait: float,
    monotonic: Callable[[], float],
) -> None:
    deadline = monotonic() + wait
    while True:
        frame = link.recv(max(deadline - monotonic(), 0.0))
        if frame is None:
            return
        packet = arp.parse(frame)
        if (
            packet is not None
            and packet.operation == arp.ARP_REPLY
            and packet.target_ip == local.address.ip  # an answer to us, not to another host
            and packet.sender_ip in wanted
            and arp.is_unicast(packet.sender_mac)
        ):
            found.setdefault(packet.sender_ip, set()).add(packet.sender_mac)


class PacketLink:
    """A Linux packet socket that sends and receives ARP frames on one interface."""

    def __init__(self, interface: str) -> None:
        try:
            self._sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(arp.ETH_P_ARP)
            )
        except PermissionError as exc:
            raise ScanError(
                "sending ARP requests needs the CAP_NET_RAW capability; run the scan as the"
                " service: sudo systemctl start netwatch-discovery.service"
            ) from exc
        # Linux before 4.20 lacks the option; outgoing copies are then parsed and ignored.
        with contextlib.suppress(OSError):
            self._sock.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
        try:
            self._sock.bind((interface, arp.ETH_P_ARP))
        except OSError as exc:
            self._sock.close()
            raise ScanError(f"cannot listen on {interface}: {exc.strerror}") from exc

    def send(self, frame: bytes) -> None:
        try:
            self._sock.send(frame)
        except OSError as exc:
            raise ScanError(f"cannot send on the interface: {exc.strerror}") from exc

    def recv(self, timeout: float) -> bytes | None:
        ready, _, _ = select.select([self._sock], [], [], timeout)
        return self._sock.recv(2048) if ready else None

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> PacketLink:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def ipv4_address(interface: str) -> IPv4Interface:
    """The interface's IPv4 address and netmask, from the kernel (Linux only)."""
    import fcntl  # not on Windows, where only the tests run

    request = struct.pack("256s", interface.encode()[:15])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            address = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)[20:24]
            netmask = fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, request)[20:24]
        except OSError as exc:
            if exc.errno == errno.EADDRNOTAVAIL:
                raise ScanError(f"{interface} has no IPv4 address") from exc
            raise ScanError(f"cannot read the address of {interface}: {exc.strerror}") from exc
    return IPv4Interface(f"{IPv4Address(address)}/{IPv4Address(netmask)}")


def read_interface(
    name: str,
    sys_class_net: Path = SYS_CLASS_NET,
    address_of: Callable[[str], IPv4Interface] = ipv4_address,
) -> LocalInterface:
    """The interface's MAC address (from sysfs) and IPv4 address (from the kernel)."""
    try:
        mac = (sys_class_net / name / "address").read_text(encoding="ascii").strip()
    except OSError:
        raise ScanError(f"no network interface named {name!r} (see: ip -br link)") from None
    return LocalInterface(name, arp.normalize_mac(mac), address_of(name))


def scan(
    name: str,
    link_factory: Callable[[str], PacketLink] = PacketLink,
    read: Callable[[str], LocalInterface] = read_interface,
) -> ScanReport:
    """Sweep the subnet of interface ``name`` and return who answered."""
    local = read(name)
    addresses = targets(local.address)
    with link_factory(name) as link:
        sightings = sweep(link, local, addresses)
    return ScanReport(local, len(addresses), tuple(sightings))
