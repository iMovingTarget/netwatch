from __future__ import annotations

from pathlib import Path

import pytest

from netwatch.config import load_settings, read_revision
from netwatch.errors import ConfigError


def test_state_dir_comes_from_systemd() -> None:
    settings = load_settings({"STATE_DIRECTORY": "/var/lib/netwatch"})
    assert settings.state_dir == Path("/var/lib/netwatch")


def test_explicit_state_dir_overrides_systemd() -> None:
    settings = load_settings(
        {"STATE_DIRECTORY": "/var/lib/netwatch", "NETWATCH_STATE_DIR": "/tmp/scratch"}
    )
    assert settings.state_dir == Path("/tmp/scratch")


def test_first_of_several_systemd_state_dirs_is_used() -> None:
    settings = load_settings({"STATE_DIRECTORY": "/var/lib/netwatch:/var/lib/other"})
    assert settings.state_dir == Path("/var/lib/netwatch")


def test_missing_state_dir_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="no state directory"):
        load_settings({})


def test_log_level_defaults_to_info_and_ignores_case() -> None:
    assert load_settings({"STATE_DIRECTORY": "/x"}).log_level == "INFO"
    assert load_settings({"STATE_DIRECTORY": "/x", "NETWATCH_LOG_LEVEL": "debug"}).log_level == (
        "DEBUG"
    )


def test_unknown_log_level_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="NETWATCH_LOG_LEVEL"):
        load_settings({"STATE_DIRECTORY": "/x", "NETWATCH_LOG_LEVEL": "loud"})


def test_revision_is_optional() -> None:
    assert read_revision({}) is None
    assert read_revision({"NETWATCH_REVISION": " abc123 "}) == "abc123"
