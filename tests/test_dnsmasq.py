from __future__ import annotations

import getpass
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netwatch import blocklist, dnsmasq, dnsprobe
from netwatch.config import load_settings
from netwatch.errors import ConfigError


def test_render_config() -> None:
    settings = load_settings(
        {
            "NETWATCH_DNS_LISTEN": "192.0.2.53",
            "NETWATCH_DNS_UPSTREAMS": "198.51.100.1,198.51.100.2",
            "NETWATCH_BLOCKLIST_DIR": "/var/lib/netwatch-blocklist",
        }
    )
    active = [
        line
        for line in dnsmasq.render_config(settings).splitlines()
        if line and not line.startswith("#")
    ]
    assert active == [
        "listen-address=192.0.2.53",
        "bind-dynamic",
        "no-resolv",
        "server=198.51.100.1",
        "server=198.51.100.2",
        "domain-needed",
        "bogus-priv",
        "cache-size=10000",
        "log-queries=extra",
        "log-async=25",
        "hostsdir=/var/lib/netwatch-blocklist",
    ]


def test_render_config_needs_a_listen_address() -> None:
    with pytest.raises(ConfigError, match="NETWATCH_DNS_LISTEN is not set"):
        dnsmasq.render_config(load_settings({}))


# The tests below run the real dnsmasq when it is installed (it is on the VM and in CI's deploy
# job; the unit tests don't need it).
needs_dnsmasq = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("dnsmasq") is None, reason="dnsmasq not installed"
)


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def running_dnsmasq(tmp_path: Path) -> Iterator[tuple[int, Path]]:
    """dnsmasq with Netwatch's config on 127.0.0.1, answering from a blocklist directory."""
    hostsdir = tmp_path / "blocklist"
    hostsdir.mkdir()
    (hostsdir / blocklist.HOSTS_FILE).write_text(
        blocklist.render({"ads.example.com"}, [], datetime.now(UTC))
    )
    settings = load_settings(
        {
            "NETWATCH_DNS_LISTEN": "127.0.0.1",
            # Replaced below by 127.0.0.1#9 where nothing listens, so forwarded queries fail
            # fast instead of leaving the machine.
            "NETWATCH_DNS_UPSTREAMS": "127.0.0.1",
            "NETWATCH_BLOCKLIST_DIR": str(hostsdir),
        }
    )
    port = _free_udp_port()
    conf = tmp_path / "netwatch.conf"
    conf.write_text(
        dnsmasq.render_config(settings).replace("server=127.0.0.1", "server=127.0.0.1#9")
        + f"port={port}\nno-hosts\nlog-facility={tmp_path / 'dnsmasq.log'}\n"
        # Started as root, dnsmasq drops to an unprivileged user before reading hostsdir,
        # and pytest's temporary directories are private. Run it as the current user.
        + f"user={getpass.getuser()}\n"
        + f"pid-file={tmp_path / 'dnsmasq.pid'}\n"
    )
    check = subprocess.run(
        ["dnsmasq", "--test", f"--conf-file={conf}"], capture_output=True, text=True
    )
    assert "syntax check OK" in check.stderr
    proc = subprocess.Popen(["dnsmasq", "--keep-in-foreground", f"--conf-file={conf}"])
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                dnsprobe.query("127.0.0.1", "ads.example.com", port=port, timeout=0.2)
                break
            except dnsprobe.ProbeError:
                continue
        yield port, hostsdir
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@needs_dnsmasq
def test_real_dnsmasq_blocks_ipv4_and_ipv6(running_dnsmasq: tuple[int, Path]) -> None:
    port, _ = running_dnsmasq
    assert dnsprobe.query("127.0.0.1", "ads.example.com", "A", port=port).answers == ("0.0.0.0",)
    assert dnsprobe.query("127.0.0.1", "ads.example.com", "AAAA", port=port).answers == ("::",)


@needs_dnsmasq
def test_real_dnsmasq_picks_up_an_updated_blocklist(
    running_dnsmasq: tuple[int, Path], tmp_path: Path
) -> None:
    port, hostsdir = running_dnsmasq
    settings = load_settings(
        {
            "NETWATCH_BLOCKLIST_DIR": str(hostsdir),
            "NETWATCH_ALLOWLIST_FILE": str(tmp_path / "allowlist.txt"),
            "NETWATCH_BLOCKLIST_URLS": "https://lists.example/hosts",
        }
    )
    blocklist.update(
        settings,
        fetch=lambda url: "0.0.0.0 tracker.example.org\n",
        min_domains=1,
        force=True,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        reply = dnsprobe.query("127.0.0.1", "tracker.example.org", port=port)
        if reply.answers == ("0.0.0.0",):
            break
        time.sleep(0.1)
    assert reply.answers == ("0.0.0.0",)
    # The old name is gone from the list, so dnsmasq forwards it to the dead upstream instead of
    # answering 0.0.0.0, and no reply comes back.
    with pytest.raises(dnsprobe.ProbeError, match="no reply"):
        dnsprobe.query("127.0.0.1", "ads.example.com", port=port, timeout=0.5)
