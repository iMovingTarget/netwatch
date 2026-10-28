"""Download blocklists and write them as one hosts file that dnsmasq watches.

dnsmasq reads every file in its ``hostsdir`` and, through inotify, re-reads a file whenever it
changes, so updating the blocklist needs no restart, no reload signal and no root: the
unprivileged updater writes a new file and renames it into place. Two details make that safe:

- The new file is written under a name starting with a dot and renamed when complete. dnsmasq
  ignores dotfiles in hostsdir, so it never sees a half-written list, and rename(2) is atomic.
- Each blocked name gets both ``0.0.0.0`` and ``::``. With only an IPv4 entry, dnsmasq answers
  A queries locally but forwards AAAA queries upstream, and IPv6 clients reach the ad server.

Before replacing the current list, the update checks the result: at least ``min_domains`` names,
and no more than half lost compared with the current file. A blocklist host that serves an error
page or an empty file would otherwise switch blocking off for the whole network.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from netwatch import __version__
from netwatch.config import Settings
from netwatch.errors import BlocklistError

HOSTS_FILE = "blocklist.hosts"
MIN_DOMAINS = 1000
MAX_LOSS = 0.5
MAX_BYTES = 64 * 1024 * 1024
FETCH_TIMEOUT_S = 60

# Names that hosts-format lists include for the local machine, not to block.
_LOCAL_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
        "0.0.0.0",
    }
)
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_COUNT_HEADER = re.compile(r"^# domains: (\d+)$", re.MULTILINE)

log = logging.getLogger("netwatch.blocklist")

Fetch = Callable[[str], str]


@dataclass(frozen=True)
class UpdateResult:
    domains: int
    previous: int | None
    allowed: int  # names removed because they are on the allowlist


def normalize(name: str) -> str | None:
    """A lower-case domain name, or None if ``name`` isn't one worth blocking."""
    name = name.strip().lower().rstrip(".")
    if name in _LOCAL_NAMES or "." not in name or len(name) > 253:
        return None
    if not all(_LABEL.match(label) for label in name.split(".")):
        return None
    return name


def parse(text: str) -> set[str]:
    """Domains from a hosts-format list ("0.0.0.0 name ...") or a plain one-per-line list."""
    domains: set[str] = set()
    for raw in text.splitlines():
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        if len(fields) >= 2 and _is_ip(fields[0]):
            names = fields[1:]
        elif len(fields) == 1:
            names = fields
        else:
            continue
        for name in names:
            domain = normalize(name)
            if domain is not None:
                domains.add(domain)
    return domains


def render(domains: Iterable[str], sources: Iterable[str], now: datetime) -> str:
    names = sorted(domains)
    lines = [
        f"# Netwatch blocklist, generated {now.isoformat(timespec='seconds')}",
        *(f"# source: {url}" for url in sources),
        f"# domains: {len(names)}",
    ]
    for name in names:
        lines.append(f"0.0.0.0 {name}")
        lines.append(f":: {name}")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Header:
    generated: str | None
    sources: tuple[str, ...]
    domains: int | None


def read_header(path: Path) -> Header | None:
    """What an existing blocklist file says about itself, or None if there is no file."""
    try:
        with path.open(encoding="utf-8") as f:
            head = "".join(next(f, "") for _ in range(20))
    except FileNotFoundError:
        return None
    generated = re.search(r"^# Netwatch blocklist, generated (\S+)$", head, re.MULTILINE)
    count = _COUNT_HEADER.search(head)
    return Header(
        generated=generated.group(1) if generated else None,
        sources=tuple(re.findall(r"^# source: (\S+)$", head, re.MULTILINE)),
        domains=int(count.group(1)) if count else None,
    )


def current_count(path: Path) -> int | None:
    """The domain count recorded in an existing blocklist file's header."""
    header = read_header(path)
    return header.domains if header else None


def read_allowlist(path: Path) -> set[str]:
    try:
        return parse(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return set()


def fetch_url(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": f"netwatch/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_S) as response:
            data = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise BlocklistError(f"{url}: HTTP {exc.code} {exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise BlocklistError(f"{url}: {reason}") from exc
    if len(data) > MAX_BYTES:
        raise BlocklistError(f"{url}: larger than {MAX_BYTES // (1024 * 1024)} MB")
    return data.decode("utf-8", "replace")


def update(
    settings: Settings,
    fetch: Fetch = fetch_url,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    force: bool = False,
    min_domains: int = MIN_DOMAINS,
) -> UpdateResult:
    """Download every configured list, check the result, and swap it into place."""
    domains: set[str] = set()
    for url in settings.blocklist_urls:
        found = parse(fetch(url))
        if not found:
            raise BlocklistError(f"{url}: no domains found (not a hosts file or domain list?)")
        log.info("%s: %d domains", url, len(found))
        domains |= found
    allow = read_allowlist(settings.allowlist_file)
    allowed = len(domains & allow)
    domains -= allow

    path = settings.blocklist_dir / HOSTS_FILE
    previous = current_count(path)
    if not force:
        if len(domains) < min_domains:
            raise BlocklistError(
                f"only {len(domains)} domains, fewer than {min_domains}; keeping the current"
                " list (use --force to install it anyway)"
            )
        if previous and len(domains) < previous * (1 - MAX_LOSS):
            raise BlocklistError(
                f"the list shrank from {previous} to {len(domains)} domains; keeping the"
                " current list (use --force to install it anyway)"
            )

    _write_atomically(path, render(domains, settings.blocklist_urls, now()))
    log.info(
        "blocklist updated: %d domains (was %s), %d allowlisted",
        len(domains),
        previous if previous is not None else "none",
        allowed,
    )
    return UpdateResult(domains=len(domains), previous=previous, allowed=allowed)


def _write_atomically(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # The leading dot keeps dnsmasq from reading the file before it is complete.
    tmp = path.with_name(f".{path.name}.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    tmp.chmod(0o644)  # dnsmasq reads it as its own user
    os.replace(tmp, path)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True
