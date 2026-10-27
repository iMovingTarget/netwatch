from __future__ import annotations

import re

import netwatch

# PEP 440 public version, e.g. 0.1.0, 0.2.0rc1, 0.1.0.dev0
PEP440 = re.compile(r"^\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$")


def test_version_is_pep440() -> None:
    assert PEP440.match(netwatch.__version__)
