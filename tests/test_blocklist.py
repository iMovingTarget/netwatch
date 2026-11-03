from __future__ import annotations

import io
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netwatch import blocklist
from netwatch.__main__ import main
from netwatch.config import Settings, load_settings
from netwatch.errors import BlocklistError

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
URL_A = "https://lists.example/hosts"
URL_B = "https://lists.example/domains"

HOSTS = """\
# A hosts-format list with the usual local header
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
255.255.255.255 broadcasthost
::1 localhost ip6-localhost ip6-loopback
0.0.0.0 0.0.0.0

0.0.0.0 ads.example.com
0.0.0.0 Tracker.Example.ORG.   # upper case and a trailing dot
0.0.0.0 a.example.net b.example.net
127.0.0.1 pixel.example.com
0.0.0.0 not_valid-.example
0.0.0.0 printer
"""


def _settings(tmp_path: Path, *urls: str) -> Settings:
    return load_settings(
        {
            "NETWATCH_BLOCKLIST_DIR": str(tmp_path / "blocklist"),
            "NETWATCH_ALLOWLIST_FILE": str(tmp_path / "allowlist.txt"),
            "NETWATCH_BLOCKLIST_URLS": ",".join(urls or (URL_A,)),
        }
    )


def _fetcher(pages: dict[str, str]) -> blocklist.Fetch:
    return lambda url: pages[url]


def test_parse_hosts_format() -> None:
    assert blocklist.parse(HOSTS) == {
        "ads.example.com",
        "tracker.example.org",
        "a.example.net",
        "b.example.net",
        "pixel.example.com",
    }


def test_parse_plain_domain_list() -> None:
    assert blocklist.parse("# comment\nads.example.com\n\nmetrics.example.net # inline\n") == {
        "ads.example.com",
        "metrics.example.net",
    }


def test_render_blocks_ipv4_and_ipv6() -> None:
    text = blocklist.render({"b.example", "a.example"}, [URL_A], NOW)
    assert text.splitlines() == [
        "# Netwatch blocklist, generated 2026-10-28T12:00:00+00:00",
        f"# source: {URL_A}",
        "# domains: 2",
        "0.0.0.0 a.example",
        ":: a.example",
        "0.0.0.0 b.example",
        ":: b.example",
    ]


def test_update_merges_sources_and_applies_the_allowlist(tmp_path: Path) -> None:
    settings = _settings(tmp_path, URL_A, URL_B)
    (tmp_path / "allowlist.txt").write_text("# needed by the bank app\npixel.example.com\n")
    fetch = _fetcher({URL_A: HOSTS, URL_B: "ads.example.com\nextra.example.net\n"})

    result = blocklist.update(settings, fetch=fetch, now=lambda: NOW, min_domains=1)

    assert result == blocklist.UpdateResult(domains=5, previous=None, allowed=1)
    path = settings.blocklist_dir / blocklist.HOSTS_FILE
    written = path.read_text()
    assert "0.0.0.0 extra.example.net\n:: extra.example.net\n" in written
    assert "pixel.example.com" not in written
    assert blocklist.read_header(path) == blocklist.Header(
        generated="2026-10-28T12:00:00+00:00", sources=(URL_A, URL_B), domains=5
    )
    assert not list(settings.blocklist_dir.glob(".*"))  # no temporary file left behind
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o644  # dnsmasq reads it as its own user


def test_too_few_domains_keeps_the_current_list(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with pytest.raises(BlocklistError, match="only 5 domains, fewer than 1000"):
        blocklist.update(settings, fetch=_fetcher({URL_A: HOSTS}), now=lambda: NOW)
    assert not (settings.blocklist_dir / blocklist.HOSTS_FILE).exists()

    result = blocklist.update(settings, fetch=_fetcher({URL_A: HOSTS}), now=lambda: NOW, force=True)
    assert result.domains == 5


def test_a_list_that_lost_more_than_half_is_refused(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    big = "\n".join(f"0.0.0.0 ad{i}.example.com" for i in range(10))
    blocklist.update(settings, fetch=_fetcher({URL_A: big}), now=lambda: NOW, min_domains=1)
    small = "\n".join(f"0.0.0.0 ad{i}.example.com" for i in range(4))

    with pytest.raises(BlocklistError, match="shrank from 10 to 4"):
        blocklist.update(settings, fetch=_fetcher({URL_A: small}), now=lambda: NOW, min_domains=1)
    assert blocklist.current_count(settings.blocklist_dir / blocklist.HOSTS_FILE) == 10


def test_a_source_with_no_domains_is_an_error(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    page = "<html><body>503 Service Unavailable</body></html>"
    with pytest.raises(BlocklistError, match="no domains found"):
        blocklist.update(settings, fetch=_fetcher({URL_A: page}), now=lambda: NOW)


BIG = "\n".join(f"0.0.0.0 ad{i}.example.com" for i in range(10))


# Found in the v0.6.0 audit: an allowlist the service can't read (root-only after an edit, a
# directory by mistake) or a blocklist directory it can't write ended in a traceback in the
# journal. The update must stop with one line, keep the current list and leave no temporary file.
def test_an_unreadable_allowlist_is_one_line_and_keeps_the_list(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    blocklist.update(settings, fetch=_fetcher({URL_A: BIG}), now=lambda: NOW, min_domains=1)
    (tmp_path / "allowlist.txt").mkdir()  # can't be read as a file, even by root

    with pytest.raises(BlocklistError, match=r"cannot read the allowlist .*allowlist\.txt"):
        blocklist.update(settings, fetch=_fetcher({URL_A: HOSTS}), now=lambda: NOW, force=True)
    assert blocklist.current_count(settings.blocklist_dir / blocklist.HOSTS_FILE) == 10


def test_a_blocklist_directory_that_cannot_be_written_is_one_line(tmp_path: Path) -> None:
    (tmp_path / "not-a-directory").write_text("")
    settings = load_settings(
        {
            "NETWATCH_BLOCKLIST_DIR": str(tmp_path / "not-a-directory" / "blocklist"),
            "NETWATCH_ALLOWLIST_FILE": str(tmp_path / "allowlist.txt"),
            "NETWATCH_BLOCKLIST_URLS": URL_A,
        }
    )
    with pytest.raises(BlocklistError, match="cannot write"):
        blocklist.update(settings, fetch=_fetcher({URL_A: BIG}), now=lambda: NOW, min_domains=1)


def test_a_failed_swap_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)

    def refuse(src: object, dst: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(blocklist.os, "replace", refuse)
    with pytest.raises(BlocklistError, match=r"cannot write .*: Permission denied"):
        blocklist.update(settings, fetch=_fetcher({URL_A: BIG}), now=lambda: NOW, min_domains=1)
    assert not list(settings.blocklist_dir.glob(".*"))


def test_blocklist_update_errors_are_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        blocklist.urllib.request, "urlopen", lambda request, timeout: io.BytesIO(BIG.encode())
    )
    (tmp_path / "allowlist").mkdir()
    env = {
        "NETWATCH_BLOCKLIST_DIR": str(tmp_path / "blocklist"),
        "NETWATCH_ALLOWLIST_FILE": str(tmp_path / "allowlist"),
        "NETWATCH_BLOCKLIST_URLS": URL_A,
    }
    assert main(["blocklist", "update"], environ=env) == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert err.count("\n") == 1


def test_fetch_errors_name_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(blocklist.urllib.request, "urlopen", refuse)
    with pytest.raises(BlocklistError, match=f"{URL_A}: connection refused"):
        blocklist.fetch_url(URL_A)


def test_status_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = {"NETWATCH_BLOCKLIST_DIR": str(tmp_path)}
    assert main(["blocklist", "status"], environ=env) == 1
    assert "no blocklist" in capsys.readouterr().err

    (tmp_path / blocklist.HOSTS_FILE).write_text(blocklist.render({"a.example"}, [URL_A], NOW))
    assert main(["blocklist", "status"], environ=env) == 0
    out = capsys.readouterr().out
    assert "generated: 2026-10-28T12:00:00+00:00" in out
    assert "domains:   1" in out


def test_read_header_of_a_file_that_cannot_be_read_is_one_line(tmp_path: Path) -> None:
    (tmp_path / blocklist.HOSTS_FILE).mkdir()  # can't be opened as a file, even by root
    with pytest.raises(BlocklistError, match="cannot read"):
        blocklist.read_header(tmp_path / blocklist.HOSTS_FILE)
    with pytest.raises(BlocklistError, match="cannot read"):
        blocklist.first_domain(tmp_path / blocklist.HOSTS_FILE)
