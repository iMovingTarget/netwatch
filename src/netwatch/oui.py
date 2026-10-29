"""MAC address vendors from the IEEE registry, as packaged by Debian and Ubuntu (ieee-data).

The first 24 bits of an IEEE-assigned MAC address are the OUI, the block IEEE assigned to a
manufacturer (MA-L). IEEE also sells smaller blocks inside its own OUIs: 28-bit (MA-M) and
36-bit (MA-S, and the older IAB), so the vendor is the longest prefix that matches. The registry
files look like this (CRLF line endings, UTF-8):

    00-00-5E   (hex)		ICANN, IANA Department
    00005E     (base 16)		ICANN, IANA Department

and, for the smaller blocks, the "(base 16)" line holds the range inside the OUI:

    8C-1F-64   (hex)		Example Org
    C16000-C16FFF     (base 16)		Example Org

Locally administered addresses (a phone's private Wi-Fi address) aren't in the registry at all.
The files are about 9 MB together and a vendor is only needed when a new device appears, so they
are read on the first lookup, not at start.
"""

from __future__ import annotations

import logging
from pathlib import Path

from netwatch.arp import is_locally_administered, normalize_mac

DEFAULT_DIR = Path("/usr/share/ieee-data")
# MA-L, MA-M, MA-S and the older IAB blocks.
FILES = ("oui.txt", "mam.txt", "oui36.txt", "iab.txt")

log = logging.getLogger("netwatch.oui")


def parse_registry(text: str) -> dict[str, str]:
    """Prefix (6, 7 or 9 upper-case hex digits) -> organisation, from one registry file."""
    prefixes: dict[str, str] = {}
    oui: str | None = None
    organisation = ""
    for line in text.splitlines():
        if "(hex)" in line:
            left, _, org = line.partition("(hex)")
            digits = left.strip().replace("-", "").upper()
            oui = digits if len(digits) == 6 and _is_hex(digits) else None
            organisation = org.strip()
        elif "(base 16)" in line and oui is not None:
            block = line.partition("(base 16)")[0].strip().upper()
            prefix = _prefix(oui, block)
            if prefix is not None and organisation:
                prefixes[prefix] = organisation
            oui = None
    return prefixes


def _prefix(oui: str, block: str) -> str | None:
    if "-" not in block:
        return oui if block == oui else None  # an MA-L entry: the whole OUI
    start, _, end = block.partition("-")
    if len(start) != 6 or len(end) != 6 or not _is_hex(start + end):
        return None
    # The range fixes the first n hex digits after the OUI: 700000-7FFFFF fixes one (MA-M),
    # C16000-C16FFF fixes three (MA-S).
    n = next((i for i in range(6) if start[i] != end[i]), 6)
    if start[n:] != "0" * (6 - n) or end[n:] != "F" * (6 - n):
        return None
    return oui + start[:n]


def _is_hex(text: str) -> bool:
    return all(ch in "0123456789ABCDEF" for ch in text)


class VendorLookup:
    """Find the organisation a MAC address was assigned to."""

    def __init__(self, directory: Path = DEFAULT_DIR) -> None:
        self.directory = directory
        self._prefixes: dict[str, str] | None = None

    def vendor(self, mac: str) -> str | None:
        """The organisation for ``mac``; None if it's locally administered or not registered."""
        if is_locally_administered(mac):
            return None
        digits = normalize_mac(mac).replace(":", "").upper()
        prefixes = self._load()
        for length in (9, 7, 6):  # longest prefix first: MA-S, MA-M, MA-L
            organisation = prefixes.get(digits[:length])
            if organisation is not None:
                return organisation
        return None

    def _load(self) -> dict[str, str]:
        if self._prefixes is None:
            self._prefixes = {}
            for name in FILES:
                try:
                    text = (self.directory / name).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                self._prefixes.update(parse_registry(text))
            if not self._prefixes:
                log.warning(
                    "no IEEE registry in %s (package ieee-data), so vendors are not shown",
                    self.directory,
                )
        return self._prefixes
