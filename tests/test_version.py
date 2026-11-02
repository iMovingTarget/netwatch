from __future__ import annotations

import re
from pathlib import Path

import netwatch

# PEP 440 public version, e.g. 0.1.0, 0.2.0rc1, 0.1.0.dev0
PEP440 = re.compile(r"^\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$")
CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
RELEASE_HEADING = re.compile(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$", re.MULTILINE)


def test_version_is_pep440() -> None:
    assert PEP440.match(netwatch.__version__)


def test_version_is_the_newest_release_in_the_changelog() -> None:
    # Regression: the 0.5.0 release commit moved the changes to "## [0.5.0]" but left
    # __version__ at 0.4.0, so the release candidate reported 0.4.0 in --version, in install.sh's
    # summary and in netwatch_build_info. Between releases the newest heading is the last release,
    # which is still the installed version; a release commit must change both.
    releases = RELEASE_HEADING.findall(CHANGELOG.read_text(encoding="utf-8"))
    assert releases, "no release heading in CHANGELOG.md"
    assert releases[0] == netwatch.__version__
