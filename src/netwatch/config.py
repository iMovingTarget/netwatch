"""Settings, read from environment variables.

In production the variables come from the systemd unit: /etc/netwatch/netwatch.env (an
EnvironmentFile readable only by root and the netwatch group, so later phases can keep secrets
there) and STATE_DIRECTORY, which systemd sets from StateDirectory=. Reading everything from the
environment keeps the code free of file paths and makes every setting easy to override in tests.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from netwatch.errors import ConfigError

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


@dataclass(frozen=True)
class Settings:
    state_dir: Path
    log_level: str
    revision: str | None


def load_settings(environ: Mapping[str, str]) -> Settings:
    """Build Settings from ``environ``. Raises ConfigError with a one-line explanation."""
    return Settings(
        state_dir=_state_dir(environ),
        log_level=_log_level(environ),
        revision=read_revision(environ),
    )


def read_revision(environ: Mapping[str, str]) -> str | None:
    """The git commit the installer deployed (NETWATCH_REVISION), or None outside a deploy."""
    return environ.get("NETWATCH_REVISION", "").strip() or None


def _state_dir(environ: Mapping[str, str]) -> Path:
    # NETWATCH_STATE_DIR wins so a developer can point Netwatch at a scratch directory.
    explicit = environ.get("NETWATCH_STATE_DIR", "").strip()
    if explicit:
        return Path(explicit)
    # Under systemd, StateDirectory= sets STATE_DIRECTORY (colon-separated if there are several).
    from_systemd = environ.get("STATE_DIRECTORY", "").strip()
    if from_systemd:
        return Path(from_systemd.split(":")[0])
    raise ConfigError(
        "no state directory: set NETWATCH_STATE_DIR (under systemd, StateDirectory= sets it)"
    )


def _log_level(environ: Mapping[str, str]) -> str:
    level = environ.get("NETWATCH_LOG_LEVEL", "").strip().upper() or "INFO"
    if level not in LOG_LEVELS:
        raise ConfigError(
            f"NETWATCH_LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}, not {level!r}"
        )
    return level
