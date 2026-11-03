from __future__ import annotations

import json
from pathlib import Path

import pytest

from netwatch.dnslog import QueryAssembler

FIXTURE = Path(__file__).parent / "fixtures" / "dnsmasq-journal.jsonl"
BLOCKLIST_DIR = "/var/lib/netwatch-blocklist"


def _records() -> list[dict[str, str]]:
    return [json.loads(line) for line in FIXTURE.read_text().splitlines()]


def test_fixture_assembles_one_record_per_query() -> None:
    # The fixture is dnsmasq 2.91 output captured with log-queries=extra: forwarded, cached,
    # CNAME, multi-record, NXDOMAIN, blocked A/AAAA, a blocked name's HTTPS query (forwarded),
    # local rules, a TCP query answered by a child process, an unanswered query, a live
    # blocklist reload and a dnsmasq restart.
    assembler = QueryAssembler(BLOCKLIST_DIR)
    queries = []
    for rec in _records():
        queries += assembler.feed(rec["MESSAGE"], int(rec["__REALTIME_TIMESTAMP"]), rec["__CURSOR"])
    queries += assembler.flush_all()

    got = [(q.serial, q.client, q.name, q.qtype, q.status, q.answer, q.upstream) for q in queries]
    up = "198.51.100.1"
    assert got == [
        (1, "192.0.2.10", "example.com", "A", "forwarded", "192.0.2.80", up),
        (2, "192.0.2.10", "example.com", "A", "cached", "192.0.2.80", None),
        (3, "192.0.2.11", "example.org", "AAAA", "forwarded", "2001:db8::81", up),
        (4, "192.0.2.11", "www.example.net", "A", "forwarded", "198.51.100.7", up),
        (5, "192.0.2.11", "www.example.net", "A", "cached", "198.51.100.7", None),
        (6, "192.0.2.10", "multi.example.com", "A", "forwarded", "192.0.2.90, 192.0.2.91", up),
        (7, "192.0.2.10", "nosuch.example", "A", "forwarded", "NXDOMAIN", up),
        (8, "192.0.2.10", "ads.example.com", "A", "blocked", "0.0.0.0", None),
        (9, "192.0.2.10", "ads.example.com", "AAAA", "blocked", "::", None),
        (10, "192.0.2.10", "ads.example.com", "HTTPS", "forwarded", "NODATA", up),
        (11, "192.0.2.11", "example.com", "TXT", "forwarded", "v=spf1 -all", up),
        (12, "192.0.2.11", "20.1.168.192.in-addr.arpa", "PTR", "local", "NXDOMAIN", None),
        (13, "192.0.2.11", "printer", "A", "local", "NXDOMAIN", None),
        (14, "192.0.2.10", "example.org", "A", "forwarded", "192.0.2.81", up),
        (114, "192.0.2.10", "host.dead.example", "A", "no-answer", None, "192.0.2.99"),
        (115, "192.0.2.10", "tracker.example.org", "A", "forwarded", "192.0.2.81", up),
        (1, "192.0.2.11", "example.com", "A", "forwarded", "192.0.2.80", up),
    ]


def _feed(assembler: QueryAssembler, lines: list[tuple[int, str]]) -> None:
    for i, (ts, message) in enumerate(lines):
        assert assembler.feed(message, ts, f"c{i}") == []


def test_answer_is_emitted_only_after_it_settles() -> None:
    assembler = QueryAssembler(BLOCKLIST_DIR, settle_us=1_000_000)
    _feed(
        assembler,
        [
            (0, "6 192.0.2.10/1 query[A] multi.example.com from 192.0.2.10"),
            (100, "6 192.0.2.10/1 reply multi.example.com is 192.0.2.90"),
        ],
    )
    assert assembler.flush(now_us=600_000) == []
    _feed(assembler, [(700_000, "6 192.0.2.10/1 reply multi.example.com is 192.0.2.91")])

    assert assembler.flush(now_us=1_600_000) == []
    [query] = assembler.flush(now_us=1_700_000)
    assert query.answer == "192.0.2.90, 192.0.2.91"


def test_unanswered_query_times_out() -> None:
    assembler = QueryAssembler(BLOCKLIST_DIR, timeout_us=10_000_000)
    _feed(
        assembler,
        [
            (0, "9 192.0.2.10/1 query[A] host.dead.example from 192.0.2.10"),
            (10, "9 192.0.2.10/1 forwarded host.dead.example to 192.0.2.99"),
        ],
    )
    assert assembler.flush(now_us=9_999_999) == []
    [query] = assembler.flush(now_us=10_000_000)
    assert (query.status, query.answer, query.upstream) == ("no-answer", None, "192.0.2.99")


def test_ipv6_client() -> None:
    assembler = QueryAssembler(BLOCKLIST_DIR)
    _feed(
        assembler,
        [
            (0, "3 2001:db8::10/40000 query[AAAA] example.org from 2001:db8::10"),
            (1, "3 2001:db8::10/40000 cached example.org is 2001:db8::81"),
        ],
    )
    [query] = assembler.flush_all()
    assert (query.client, query.status) == ("2001:db8::10", "cached")


@pytest.mark.parametrize(
    "name",
    [
        # What dnsmasq logs in place of a name with a byte it can't print: a control character,
        # anything outside ASCII. Any client can send such a name.
        "<name unprintable>",
        # A space is printable, so dnsmasq logs it as it is.
        "two words.example.com",
        # The words the log lines are built from, inside a name.
        "a from b is c to d.example.com",
    ],
)
def test_names_with_spaces_are_stored(name: str) -> None:
    # Found in the v0.6.0 audit: the parser took a name to be one word, so these queries were
    # logged by dnsmasq but never stored, and a client could keep its lookups out of Netwatch.
    assembler = QueryAssembler(BLOCKLIST_DIR)
    _feed(
        assembler,
        [
            (0, f"4 192.0.2.10/1 query[A] {name} from 192.0.2.10"),
            (1, f"4 192.0.2.10/1 forwarded {name} to 198.51.100.1"),
            (2, f"4 192.0.2.10/1 reply {name} is NODATA-IPv4"),
        ],
    )
    [query] = assembler.flush_all()
    assert (query.name, query.qtype, query.client, query.status, query.upstream) == (
        name,
        "A",
        "192.0.2.10",
        "forwarded",
        "198.51.100.1",
    )


def test_an_answer_with_spaces_keeps_them() -> None:
    assembler = QueryAssembler(BLOCKLIST_DIR)
    _feed(
        assembler,
        [
            (0, "5 192.0.2.10/1 query[TXT] example.com from 192.0.2.10"),
            (1, "5 192.0.2.10/1 reply example.com is this is a test"),
        ],
    )
    [query] = assembler.flush_all()
    assert query.answer == "this is a test"


def test_resume_cursor_is_the_oldest_pending_query() -> None:
    assembler = QueryAssembler(BLOCKLIST_DIR)
    assert assembler.resume_cursor() is None
    assembler.feed("1 192.0.2.10/1 query[A] a.example from 192.0.2.10", 10, "cursor-a")
    assembler.feed("2 192.0.2.10/2 query[A] b.example from 192.0.2.10", 20, "cursor-b")
    assembler.feed("1 192.0.2.10/1 cached a.example is 192.0.2.1", 30, "cursor-c")
    assert assembler.resume_cursor() == "cursor-a"

    assembler.flush(now_us=30 + 1_000_000)  # a.example settles; b.example is still waiting
    assert assembler.resume_cursor() == "cursor-b"


def test_restart_emits_pending_queries() -> None:
    assembler = QueryAssembler(BLOCKLIST_DIR)
    assembler.feed("1 192.0.2.10/1 query[A] a.example from 192.0.2.10", 10, "c1")
    [query] = assembler.feed("started, version 2.92 cachesize 10000", 20, "c2")
    assert (query.name, query.status) == ("a.example", "no-answer")


def test_lines_without_a_known_query_are_ignored() -> None:
    assembler = QueryAssembler(BLOCKLIST_DIR)
    for message in (
        "7 192.0.2.10/1 reply orphan.example is 192.0.2.1",
        "read /var/lib/netwatch-blocklist/blocklist.hosts - 4 names",
        "inotify: /var/lib/netwatch-blocklist/blocklist.hosts new or modified",
        "cleared cache",
        "",
    ):
        assert assembler.feed(message, 0, "c") == []
    assert assembler.flush_all() == []
