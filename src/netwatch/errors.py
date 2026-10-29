"""Exceptions for problems the user can cause and fix.

The command-line entry point turns these into a one-line message on stderr and a non-zero exit
code. Anything else is a bug and keeps its traceback.
"""

from __future__ import annotations


class NetwatchError(Exception):
    """Base class for errors that are shown to the user as a single line."""

    exit_code = 1


class ConfigError(NetwatchError):
    """A setting is missing or invalid."""

    exit_code = 2


class StorageError(NetwatchError):
    """The database can't be opened, or it was written by a newer Netwatch."""


class BlocklistError(NetwatchError):
    """A blocklist couldn't be downloaded, or the result failed a sanity check."""


class ScanError(NetwatchError):
    """The LAN can't be scanned: no such interface, no IPv4 address, or no permission."""
