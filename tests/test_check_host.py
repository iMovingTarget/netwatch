"""Tests for the helper functions in deploy/check-host.sh, run through bash."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "check-host.sh"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="check-host.sh targets Linux",
)


def _call(function: str, *args: str) -> str:
    """Source check-host.sh (which skips the report) and call one helper function."""
    result = subprocess.run(
        # $0 is a placeholder name so the script's "executed, not sourced" check stays false.
        ["bash", "-c", f'source "$1" && shift && {function} "$@"', "test", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_stub_listener_setting_without_dropin_dir(tmp_path: Path) -> None:
    # Regression: the VM has resolved.conf but no resolved.conf.d/. grep then exits 2 even
    # though it matched, and the report printed both the real value and "not set".
    _write(tmp_path / "etc/systemd/resolved.conf", "[Resolve]\nDNSStubListener=no\n")

    out = _call("stub_listener_setting", str(tmp_path))

    assert "DNSStubListener=no" in out
    assert "not set" not in out


def test_stub_listener_setting_from_dropin(tmp_path: Path) -> None:
    _write(tmp_path / "etc/systemd/resolved.conf", "[Resolve]\n#DNSStubListener=yes\n")
    _write(
        tmp_path / "etc/systemd/resolved.conf.d/netwatch.conf", "[Resolve]\nDNSStubListener=no\n"
    )

    out = _call("stub_listener_setting", str(tmp_path))

    assert "resolved.conf.d/netwatch.conf:DNSStubListener=no" in out
    assert "not set" not in out


def test_stub_listener_default_when_unset(tmp_path: Path) -> None:
    _write(tmp_path / "etc/systemd/resolved.conf", "[Resolve]\n#DNSStubListener=yes\n")

    assert _call("stub_listener_setting", str(tmp_path)).strip() == (
        "DNSStubListener not set (default: yes)"
    )
