from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from netwatch.config import environ_with_env_file, load_settings, read_env_file, read_revision
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


def test_state_dir_defaults_to_the_production_path() -> None:
    assert load_settings({}).state_dir == Path("/var/lib/netwatch")


def test_log_level_defaults_to_info_and_ignores_case() -> None:
    assert load_settings({"STATE_DIRECTORY": "/x"}).log_level == "INFO"
    assert load_settings({"STATE_DIRECTORY": "/x", "NETWATCH_LOG_LEVEL": "debug"}).log_level == (
        "DEBUG"
    )


def test_unknown_log_level_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="NETWATCH_LOG_LEVEL"):
        load_settings({"STATE_DIRECTORY": "/x", "NETWATCH_LOG_LEVEL": "loud"})


def test_revision_is_optional(tmp_path: Path) -> None:
    assert read_revision({}, release_dir=tmp_path) is None
    assert read_revision({"NETWATCH_REVISION": " abc123 "}, release_dir=tmp_path) == "abc123"


def test_revision_falls_back_to_the_release_directory(tmp_path: Path) -> None:
    # Regression: `netwatch --version` from a shell showed no revision, because only the
    # services load revision.env.
    (tmp_path / "revision.env").write_text("NETWATCH_REVISION=feedface\nNETWATCH_REF=v0.2.0\n")
    assert read_revision({}, release_dir=tmp_path) == "feedface"
    assert read_revision({"NETWATCH_REVISION": "abc123"}, release_dir=tmp_path) == "abc123"


def test_dns_defaults() -> None:
    settings = load_settings({})
    assert settings.dns_listen == ()
    assert settings.dns_allow_from == ()
    assert settings.dns_upstreams == ("1.1.1.1", "9.9.9.9")
    assert settings.blocklist_urls[0].startswith("https://raw.githubusercontent.com/StevenBlack/")
    assert settings.blocklist_dir == Path("/var/lib/netwatch-blocklist")
    assert settings.dns_retention_days == 30


def test_dns_settings_are_comma_separated_and_validated() -> None:
    settings = load_settings(
        {
            "NETWATCH_DNS_LISTEN": "192.0.2.53, 2001:db8::53",
            "NETWATCH_DNS_ALLOW_FROM": "192.0.2.0/24",
            "NETWATCH_DNS_UPSTREAMS": "198.51.100.1",
            "NETWATCH_DNS_RETENTION_DAYS": "7",
        }
    )
    assert settings.dns_listen == ("192.0.2.53", "2001:db8::53")
    assert settings.dns_allow_from == ("192.0.2.0/24",)
    assert settings.dns_upstreams == ("198.51.100.1",)
    assert settings.dns_retention_days == 7


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("NETWATCH_DNS_LISTEN", "router.lan", "not an IP address"),
        ("NETWATCH_DNS_ALLOW_FROM", "192.0.2.1/24", "not a network"),
        ("NETWATCH_DNS_UPSTREAMS", "1.1.1.1,dns.example", "not an IP address"),
        ("NETWATCH_BLOCKLIST_URLS", "http://example.com/hosts", "must be an https:// URL"),
        ("NETWATCH_DNS_RETENTION_DAYS", "0", "whole number of days"),
    ],
)
def test_invalid_dns_settings_are_config_errors(key: str, value: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_settings({key: value})


def test_env_file_parsing(tmp_path: Path) -> None:
    env_file = tmp_path / "netwatch.env"
    env_file.write_text(
        '# comment\n\nNETWATCH_LOG_LEVEL=DEBUG\nNETWATCH_DNS_LISTEN = "192.0.2.53"\nnot a setting\n'
    )
    assert read_env_file(str(env_file)) == {
        "NETWATCH_LOG_LEVEL": "DEBUG",
        "NETWATCH_DNS_LISTEN": "192.0.2.53",
    }
    assert read_env_file(str(tmp_path / "missing.env")) == {}


def test_real_environment_overrides_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / "netwatch.env"
    env_file.write_text("NETWATCH_LOG_LEVEL=DEBUG\nNETWATCH_DNS_LISTEN=192.0.2.53\n")
    merged = environ_with_env_file(
        {"NETWATCH_ENV_FILE": str(env_file), "NETWATCH_LOG_LEVEL": "ERROR"}
    )
    assert merged["NETWATCH_LOG_LEVEL"] == "ERROR"
    assert merged["NETWATCH_DNS_LISTEN"] == "192.0.2.53"


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions, not root"
)
def test_unreadable_env_file_is_a_config_error(tmp_path: Path) -> None:
    env_file = tmp_path / "netwatch.env"
    env_file.write_text("NETWATCH_LOG_LEVEL=DEBUG\n")
    env_file.chmod(0)
    with pytest.raises(ConfigError, match="cannot read"):
        read_env_file(str(env_file))
