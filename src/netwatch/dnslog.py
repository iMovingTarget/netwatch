"""Turn dnsmasq's query log into one record per DNS query.

With ``log-queries=extra`` dnsmasq writes several lines for each query. Every line starts with a
serial number for the query and the client's address and port, so lines can be matched up even
when queries from different clients interleave::

    8 192.0.2.10/57932 query[A] ads.example.com from 192.0.2.10
    8 192.0.2.10/57932 /var/lib/netwatch-blocklist/blocklist.hosts ads.example.com is 0.0.0.0

The line that answers a query names its source: ``reply`` (from the upstream server), ``cached``,
``config`` (dnsmasq's own rules, such as refusing to forward single-label names) or the hosts file
the answer came from. Netwatch's blocklist is a hosts file in its own directory, so "blocked" is
read straight from dnsmasq's log rather than guessed by comparing names against the list.

dnsmasq never logs "this query is finished": a reply can span several lines (one per record, plus
CNAME steps). QueryAssembler therefore emits a query once its answer has been quiet for a short
settle time, and gives up on a query with no answer after a timeout.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# "<serial> <client>/<port> <rest>"; the client may be IPv4 or IPv6.
_LINE = re.compile(r"^(?P<serial>\d+) (?P<client>\S+)/(?P<port>\d+) (?P<rest>.+)$")
_QUERY = re.compile(r"^query\[(?P<qtype>[^\]]+)\] (?P<name>\S+) from \S+$")
_FORWARDED = re.compile(r"^forwarded (?P<name>\S+) to (?P<upstream>\S+)$")
_ANSWER = re.compile(r"^(?P<source>\S+) (?P<name>\S+) is (?P<value>.+)$")

_RESTART_PREFIX = "started, version "

STATUS_FORWARDED = "forwarded"
STATUS_CACHED = "cached"
STATUS_BLOCKED = "blocked"
STATUS_LOCAL = "local"
STATUS_NO_ANSWER = "no-answer"

SETTLE_US = 1_000_000
TIMEOUT_US = 10_000_000


@dataclass(frozen=True)
class DnsQuery:
    """One client query and how it was answered."""

    ts_us: int  # when dnsmasq logged the query, microseconds since the Unix epoch
    serial: int
    client: str
    name: str
    qtype: str
    status: str
    answer: str | None
    upstream: str | None


@dataclass
class _Pending:
    ts_us: int
    serial: int
    client: str
    name: str
    qtype: str
    cursor: str
    last_us: int
    upstream: str | None = None
    source: str | None = None
    values: list[str] = field(default_factory=list)


class QueryAssembler:
    """Collect dnsmasq log lines by serial number and emit completed queries.

    ``blocklist_dir`` is the directory of Netwatch's hosts-format blocklists; an answer whose
    source is a file in it means the query was blocked.
    """

    def __init__(
        self,
        blocklist_dir: str,
        settle_us: int = SETTLE_US,
        timeout_us: int = TIMEOUT_US,
    ) -> None:
        self._blocklist_prefix = blocklist_dir.rstrip("/") + "/"
        self._settle_us = settle_us
        self._timeout_us = timeout_us
        self._pending: dict[int, _Pending] = {}

    def feed(self, message: str, ts_us: int, cursor: str) -> list[DnsQuery]:
        """Process one log message. Returns queries completed by it (only on a dnsmasq restart)."""
        if message.startswith(_RESTART_PREFIX):
            # Serial numbers start again from 1, so nothing pending can be matched any more.
            return self.flush_all()
        line = _LINE.match(message)
        if line is None:
            return []
        serial = int(line["serial"])
        rest = line["rest"]

        query = _QUERY.match(rest)
        if query is not None:
            self._pending[serial] = _Pending(
                ts_us=ts_us,
                serial=serial,
                client=line["client"],
                name=query["name"],
                qtype=query["qtype"],
                cursor=cursor,
                last_us=ts_us,
            )
            return []

        pending = self._pending.get(serial)
        if pending is None:
            return []
        pending.last_us = ts_us
        forwarded = _FORWARDED.match(rest)
        if forwarded is not None:
            pending.upstream = forwarded["upstream"]
            return []
        answer = _ANSWER.match(rest)
        if answer is not None:
            if pending.source is None:
                pending.source = answer["source"]
            if answer["value"] != "<CNAME>":
                pending.values.append(answer["value"])
        return []

    def flush(self, now_us: int) -> list[DnsQuery]:
        """Emit queries whose answer has settled, or that waited too long for one."""
        done = [
            p
            for p in self._pending.values()
            if (p.source is not None and now_us - p.last_us >= self._settle_us)
            or now_us - p.ts_us >= self._timeout_us
        ]
        return self._emit(done)

    def flush_all(self) -> list[DnsQuery]:
        """Emit everything pending, answered or not."""
        return self._emit(list(self._pending.values()))

    def resume_cursor(self) -> str | None:
        """Journal cursor of the oldest pending query's first line, if any query is pending.

        Reading the journal again from there (inclusive) loses nothing after a restart; queries
        already stored come round again and are ignored because they are stored idempotently.
        """
        if not self._pending:
            return None
        return min(self._pending.values(), key=lambda p: p.ts_us).cursor

    def _emit(self, done: list[_Pending]) -> list[DnsQuery]:
        for p in done:
            del self._pending[p.serial]
        done.sort(key=lambda p: (p.ts_us, p.serial))
        return [self._to_query(p) for p in done]

    def _to_query(self, p: _Pending) -> DnsQuery:
        return DnsQuery(
            ts_us=p.ts_us,
            serial=p.serial,
            client=p.client,
            name=p.name,
            qtype=p.qtype,
            status=self._status(p.source),
            answer=", ".join(p.values) or None,
            upstream=p.upstream,
        )

    def _status(self, source: str | None) -> str:
        if source is None:
            return STATUS_NO_ANSWER
        if source == "reply":
            return STATUS_FORWARDED
        if source.startswith("cached"):  # "cached", or "cached-stale" with use-stale-cache
            return STATUS_CACHED
        if source.startswith(self._blocklist_prefix):
            return STATUS_BLOCKED
        return STATUS_LOCAL  # "config" rules, /etc/hosts and other local data
