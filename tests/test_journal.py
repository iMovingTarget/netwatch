from __future__ import annotations

import json

from netwatch import journal


def test_command_starts_at_the_end_without_a_cursor() -> None:
    assert journal.command(["--unit=x.service"], None, inclusive=True) == [
        "journalctl",
        "--unit=x.service",
        "--output=json",
        "--all",
        "--follow",
        "--no-pager",
        "--lines=0",
    ]


def test_command_resumes_at_or_after_the_cursor() -> None:
    matches = ["--identifier=sshd", "--identifier=sshd-session"]
    assert journal.command(matches, "s=a;i=1", inclusive=True)[-1] == "--cursor=s=a;i=1"
    assert journal.command(matches, "s=a;i=1", inclusive=False)[-1] == "--after-cursor=s=a;i=1"
    assert journal.command(matches, None, inclusive=False)[1:3] == matches


def test_parse_record() -> None:
    record = {"MESSAGE": "cleared cache", "__CURSOR": "c1", "__REALTIME_TIMESTAMP": "123"}
    parsed = journal.parse_record(json.dumps(record).encode())
    assert parsed == ("cleared cache", 123, "c1")
    assert (parsed.message, parsed.ts_us, parsed.cursor) == ("cleared cache", 123, "c1")
    # journald exports a message that isn't valid UTF-8 as an array of bytes
    record["MESSAGE"] = [104, 105, 0xFF]
    assert journal.parse_record(json.dumps(record).encode()) == ("hi�", 123, "c1")
    assert journal.parse_record(b"not json") is None
    assert journal.parse_record(b"[1, 2]") is None
    assert journal.parse_record(b'{"MESSAGE": "no cursor"}') is None
