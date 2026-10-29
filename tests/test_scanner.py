from __future__ import annotations

import sys
from collections import deque
from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path

import pytest

from netwatch import arp, scanner
from netwatch.errors import ScanError
from netwatch.scanner import LocalInterface, Sighting

LOCAL = LocalInterface("eth0", "00:00:5e:00:53:01", IPv4Interface("192.0.2.53/24"))
LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="packet sockets are Linux-only")


class FakeNetwork:
    """A LAN: answers ARP requests for the devices it holds, as they would."""

    def __init__(self, devices: dict[str, str], sleepy: set[str] = frozenset()) -> None:
        self.devices = {IPv4Address(ip): mac for ip, mac in devices.items()}
        self.sleepy = {IPv4Address(ip) for ip in sleepy}  # miss the first request
        self.asked: list[IPv4Address] = []
        self.inbox: deque[bytes] = deque()
        self.now = 0.0

    def send(self, frame: bytes) -> None:
        packet = arp.parse(frame)
        assert packet is not None and packet.operation == arp.ARP_REQUEST
        assert (packet.sender_mac, packet.sender_ip) == (LOCAL.mac, LOCAL.address.ip)
        target = packet.target_ip
        self.asked.append(target)
        if target in self.sleepy:
            self.sleepy.discard(target)
        elif target in self.devices:
            self.inbox.append(arp.reply(self.devices[target], target, LOCAL.mac, LOCAL.address.ip))

    def recv(self, timeout: float) -> bytes | None:
        if self.inbox:
            return self.inbox.popleft()
        self.now += timeout  # nothing more will arrive: the wait runs out
        return None

    def sweep(self, addresses: list[IPv4Address]) -> list[Sighting]:
        return scanner.sweep(
            self, LOCAL, addresses, monotonic=lambda: self.now, sleep=lambda s: None
        )


def test_targets_are_every_host_but_this_one() -> None:
    addresses = scanner.targets(LOCAL.address)
    assert len(addresses) == 253
    assert addresses[0] == IPv4Address("192.0.2.1")
    assert addresses[-1] == IPv4Address("192.0.2.254")
    assert LOCAL.address.ip not in addresses


@pytest.mark.parametrize(
    ("address", "message"),
    [
        ("10.0.0.5/16", "10.0.0.0/16 has 65536 addresses; Netwatch scans at most 1024"),
        ("192.0.2.53/32", "has no other addresses to scan"),
    ],
)
def test_networks_too_big_or_too_small_are_refused(address: str, message: str) -> None:
    with pytest.raises(ScanError, match=message):
        scanner.targets(IPv4Interface(address))


def test_a_slash_22_is_allowed() -> None:
    assert len(scanner.targets(IPv4Interface("198.51.100.1/22"))) == 1021


def test_sweep_finds_every_device_that_answers() -> None:
    network = FakeNetwork({"192.0.2.1": "00:00:5e:00:53:a1", "192.0.2.10": "02:00:5e:00:53:0a"})
    assert network.sweep(scanner.targets(LOCAL.address)) == [
        Sighting("192.0.2.1", "00:00:5e:00:53:a1"),
        Sighting("192.0.2.10", "02:00:5e:00:53:0a"),
    ]


def test_second_pass_asks_only_the_silent_addresses_and_finds_sleepy_devices() -> None:
    network = FakeNetwork(
        {"192.0.2.1": "00:00:5e:00:53:a1", "192.0.2.97": "02:00:5e:00:53:63"},
        sleepy={"192.0.2.97"},
    )
    addresses = scanner.targets(LOCAL.address)
    found = network.sweep(addresses)
    assert [s.ip for s in found] == ["192.0.2.1", "192.0.2.97"]
    assert len(network.asked) == 253 + 252  # everyone, then everyone but the router


def test_replies_not_meant_for_this_scan_are_ignored() -> None:
    network = FakeNetwork({})
    router = IPv4Address("192.0.2.1")
    other_host = IPv4Address("192.0.2.77")
    network.inbox.extend(
        [
            # a reply to another host's question
            arp.reply("00:00:5e:00:53:a1", router, "00:00:5e:00:53:77", other_host),
            # another host asking (requests carry the sender's address too)
            arp.request("00:00:5e:00:53:77", other_host, router),
            # an address outside the subnet
            arp.reply(
                "00:00:5e:00:53:b1", IPv4Address("198.51.100.1"), LOCAL.mac, LOCAL.address.ip
            ),
            # a multicast sender address: not a device
            arp.reply("01:00:5e:00:00:01", router, LOCAL.mac, LOCAL.address.ip),
            b"not a frame",
        ]
    )
    assert network.sweep(scanner.targets(LOCAL.address)) == []


def test_two_devices_claiming_one_address_are_both_reported() -> None:
    network = FakeNetwork({"192.0.2.1": "00:00:5e:00:53:a1"})
    network.inbox.append(
        arp.reply("00:00:5e:00:53:66", IPv4Address("192.0.2.1"), LOCAL.mac, LOCAL.address.ip)
    )
    assert {s.mac for s in network.sweep([IPv4Address("192.0.2.1")])} == {
        "00:00:5e:00:53:a1",
        "00:00:5e:00:53:66",
    }


def test_read_interface_from_sysfs(tmp_path: Path) -> None:
    (tmp_path / "eth0").mkdir()
    (tmp_path / "eth0" / "address").write_text("00:00:5E:00:53:01\n")
    local = scanner.read_interface(
        "eth0", sys_class_net=tmp_path, address_of=lambda name: IPv4Interface("192.0.2.53/24")
    )
    assert local == LOCAL


def test_unknown_interface_is_a_scan_error(tmp_path: Path) -> None:
    with pytest.raises(ScanError, match=r"no network interface named 'wlan9' \(see: ip -br link\)"):
        scanner.read_interface("wlan9", sys_class_net=tmp_path)


@LINUX_ONLY
def test_missing_capability_is_explained(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(scanner.socket, "socket", refuse)
    with pytest.raises(ScanError, match="needs the CAP_NET_RAW capability"):
        scanner.PacketLink("eth0")


@LINUX_ONLY
def test_loopback_has_its_address_read_from_the_kernel() -> None:
    assert scanner.ipv4_address("lo").ip == IPv4Address("127.0.0.1")
