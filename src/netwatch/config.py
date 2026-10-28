"""Settings, read from environment variables.

Services get their variables from systemd: /etc/netwatch/netwatch.env (an EnvironmentFile readable
only by root and the netwatch group, so it can hold secrets) and STATE_DIRECTORY, which systemd
sets from StateDirectory=. When netwatch runs from a shell, the entry point reads the same file
itself (see read_env_file), with the real environment taking precedence. Reading everything from
the environment keeps the code free of hard-wired paths and makes every setting easy to override
in tests.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from netwatch.errors import ConfigError

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

DEFAULT_ENV_FILE = "/etc/netwatch/netwatch.env"
DEFAULT_STATE_DIR = "/var/lib/netwatch"
DEFAULT_BLOCKLIST_DIR = "/var/lib/netwatch-blocklist"
DEFAULT_UPSTREAMS = ("1.1.1.1", "9.9.9.9")
DEFAULT_BLOCKLIST_URLS = ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",)
DEFAULT_RETENTION_DAYS = 30


@dataclass(frozen=True)
class Settings:
    state_dir: Path
    log_level: str
    revision: str | None
    dns_listen: tuple[str, ...]  # addresses dnsmasq answers on; empty means DNS is not set up
    dns_allow_from: tuple[str, ...]  # networks allowed through the firewall to port 53
    dns_upstreams: tuple[str, ...]
    blocklist_urls: tuple[str, ...]
    blocklist_dir: Path
    dns_retention_days: int


def load_settings(environ: Mapping[str, str]) -> Settings:
    """Build Settings from ``environ``. Raises ConfigError with a one-line explanation."""
    return Settings(
        state_dir=_state_dir(environ),
        log_level=_log_level(environ),
        revision=read_revision(environ),
        dns_listen=_addresses(environ, "NETWATCH_DNS_LISTEN", ()),
        dns_allow_from=_networks(environ, "NETWATCH_DNS_ALLOW_FROM"),
        dns_upstreams=_addresses(environ, "NETWATCH_DNS_UPSTREAMS", DEFAULT_UPSTREAMS),
        blocklist_urls=_urls(environ, "NETWATCH_BLOCKLIST_URLS", DEFAULT_BLOCKLIST_URLS),
        blocklist_dir=Path(
            environ.get("NETWATCH_BLOCKLIST_DIR", "").strip() or DEFAULT_BLOCKLIST_DIR
        ),
        dns_retention_days=_positive_int(
            environ, "NETWATCH_DNS_RETENTION_DAYS", DEFAULT_RETENTION_DAYS
        ),
    )


def read_revision(environ: Mapping[str, str]) -> str | None:
    """The git commit the installer deployed (NETWATCH_REVISION), or None outside a deploy."""
    return environ.get("NETWATCH_REVISION", "").strip() or None


def read_env_file(path: str) -> dict[str, str]:
    """Parse a systemd EnvironmentFile: KEY=value lines, '#' comments, optional quotes.

    A missing file gives an empty dict. A file that exists but can't be read is an error, because
    silently running without it would use defaults that differ from what the services use.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ConfigError(
            f"cannot read {path}: {exc.strerror} (run as root or as the netwatch user)"
        ) from exc
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def environ_with_env_file(environ: Mapping[str, str]) -> dict[str, str]:
    """``environ`` on top of the settings file named by NETWATCH_ENV_FILE (or the default)."""
    path = environ.get("NETWATCH_ENV_FILE", "").strip() or DEFAULT_ENV_FILE
    return {**read_env_file(path), **environ}


def _state_dir(environ: Mapping[str, str]) -> Path:
    # NETWATCH_STATE_DIR wins so a developer can point Netwatch at a scratch directory.
    explicit = environ.get("NETWATCH_STATE_DIR", "").strip()
    if explicit:
        return Path(explicit)
    # Under systemd, StateDirectory= sets STATE_DIRECTORY (colon-separated if there are several).
    from_systemd = environ.get("STATE_DIRECTORY", "").strip()
    if from_systemd:
        return Path(from_systemd.split(":")[0])
    return Path(DEFAULT_STATE_DIR)


def _log_level(environ: Mapping[str, str]) -> str:
    level = environ.get("NETWATCH_LOG_LEVEL", "").strip().upper() or "INFO"
    if level not in LOG_LEVELS:
        raise ConfigError(
            f"NETWATCH_LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}, not {level!r}"
        )
    return level


def _items(environ: Mapping[str, str], key: str) -> list[str]:
    return [item.strip() for item in environ.get(key, "").split(",") if item.strip()]


def _addresses(environ: Mapping[str, str], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    items = _items(environ, key)
    for item in items:
        try:
            ipaddress.ip_address(item)
        except ValueError:
            raise ConfigError(f"{key}: {item!r} is not an IP address") from None
    return tuple(items) or default


def _networks(environ: Mapping[str, str], key: str) -> tuple[str, ...]:
    networks = []
    for item in _items(environ, key):
        try:
            networks.append(str(ipaddress.ip_network(item, strict=True)))
        except ValueError:
            raise ConfigError(f"{key}: {item!r} is not a network such as 192.0.2.0/24") from None
    return tuple(networks)


def _urls(environ: Mapping[str, str], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    items = _items(environ, key)
    for item in items:
        if not item.startswith("https://"):
            raise ConfigError(f"{key}: {item!r} must be an https:// URL")
    return tuple(items) or default


def _positive_int(environ: Mapping[str, str], key: str, default: int) -> int:
    raw = environ.get(key, "").strip()
    if not raw:
        return default
    if not raw.isdigit() or int(raw) == 0:
        raise ConfigError(f"{key} must be a whole number of days, not {raw!r}")
    return int(raw)
