"""Prometheus metrics for node_exporter's textfile collector (``netwatch metrics``).

netwatch-metrics.timer runs ``netwatch metrics --output FILE`` once a minute. It reads the
database without changing it and writes the Prometheus text format to a file that node_exporter
serves along with the host's own metrics. Netwatch itself never listens on the network, and the
service that writes the file has no network access at all.

Counts are counters: the rows stored plus the rows retention has deleted
(storage.delete_counted), so they only ever grow and ``rate()`` works on them. Every known label
value is written even when its count is 0, so a series exists before its first event.

Domain names, client addresses and MAC addresses never become labels. Each distinct label value
is a separate time series in Prometheus, and those values are unbounded; per-name and per-device
detail stays in the database and the CLI.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from netwatch import __version__, authlog, blocklist, discovery, dnslog, storage
from netwatch.alerts import SEVERITY_CRITICAL, SEVERITY_WARNING
from netwatch.config import Settings, read_revision
from netwatch.errors import NetwatchError
from netwatch.ingest import DB_NAME

DNS_STATUSES = (
    dnslog.STATUS_FORWARDED,
    dnslog.STATUS_CACHED,
    dnslog.STATUS_BLOCKED,
    dnslog.STATUS_LOCAL,
    dnslog.STATUS_NO_ANSWER,
)
LOGIN_OUTCOMES = (authlog.OUTCOME_FAILED, authlog.OUTCOME_ACCEPTED)
ALERT_KINDS = (
    (authlog.KIND_BRUTE_FORCE, SEVERITY_WARNING),
    (authlog.KIND_LOGIN_AFTER_FAILURES, SEVERITY_CRITICAL),
    (discovery.KIND_NEW_DEVICE, SEVERITY_WARNING),
)

Labels = tuple[tuple[str, str], ...]


@dataclass
class Metric:
    name: str
    kind: str  # "counter" or "gauge"
    help: str
    samples: list[tuple[Labels, float]] = field(default_factory=list)

    def add(self, value: float, **labels: str) -> Metric:
        self.samples.append((tuple(labels.items()), value))
        return self


def collect(
    conn: sqlite3.Connection,
    settings: Settings,
    db_path: Path,
    now: datetime,
    revision: str | None = None,
) -> list[Metric]:
    """Read everything in one read transaction, so the numbers agree with each other."""
    build = Metric("netwatch_build_info", "gauge", "Version of Netwatch writing these metrics.")
    build.add(1, version=__version__, revision=(revision or "unknown")[:12])
    conn.execute("BEGIN")
    try:
        found = [
            build,
            *_dns(conn),
            *_logins(conn),
            _alerts(conn),
            *_devices(conn),
            *_blocklist(settings.blocklist_dir / blocklist.HOSTS_FILE),
            Metric(
                "netwatch_database_size_bytes",
                "gauge",
                "Size of the database file and its write-ahead log.",
            ).add(_database_size(db_path)),
            Metric(
                "netwatch_metrics_generated_timestamp_seconds",
                "gauge",
                "When these metrics were written; old means the metrics timer stopped.",
            ).add(now.timestamp()),
        ]
    finally:
        conn.execute("COMMIT")
    return found


def render(metrics: Iterable[Metric]) -> str:
    """The Prometheus text exposition format, version 0.0.4."""
    lines: list[str] = []
    for metric in metrics:
        if not metric.samples:
            continue
        lines.append(f"# HELP {metric.name} {metric.help}")
        lines.append(f"# TYPE {metric.name} {metric.kind}")
        for labels, value in metric.samples:
            lines.append(f"{metric.name}{_labels(labels)} {_number(value)}")
    return "\n".join(lines) + "\n"


def write(path: Path, text: str) -> None:
    """Replace ``path`` in one step, so node_exporter never reads half a file."""
    # node_exporter reads only *.prom files, so the temporary name is never picked up.
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        with tmp.open("w", encoding="ascii") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        tmp.chmod(0o644)  # node_exporter reads it as its own user
        os.replace(tmp, path)
    except OSError as exc:
        raise NetwatchError(f"cannot write {path}: {exc.strerror or exc}") from exc


def _dns(conn: sqlite3.Connection) -> list[Metric]:
    counts = _counts(conn, "dns_queries", "status", DNS_STATUSES)
    queries = Metric(
        "netwatch_dns_queries_total",
        "counter",
        "DNS queries from LAN clients, by how dnsmasq answered them.",
    )
    for (status,), count in counts.items():
        queries.add(count, status=status)
    last = Metric(
        "netwatch_dns_last_query_timestamp_seconds",
        "gauge",
        "When the newest stored DNS query was made.",
    )
    newest = conn.execute("SELECT max(ts_us) FROM dns_queries").fetchone()[0]
    if newest is not None:
        last.add(newest / 1_000_000)
    return [queries, last]


def _logins(conn: sqlite3.Connection) -> list[Metric]:
    counts = _counts(conn, "auth_events", "outcome", LOGIN_OUTCOMES)
    logins = Metric(
        "netwatch_ssh_logins_total",
        "counter",
        "SSH logins to this host, failed and accepted.",
    )
    for (outcome,), count in counts.items():
        logins.add(count, outcome=outcome)
    return [logins]


def _alerts(conn: sqlite3.Connection) -> Metric:
    counts: dict[tuple[str, ...], int] = {pair: 0 for pair in ALERT_KINDS}
    for kind, severity, count in conn.execute(
        "SELECT kind, severity, count(*) FROM alerts GROUP BY kind, severity"
    ):
        counts[(kind, severity)] = counts.get((kind, severity), 0) + count
    for key, count in storage.deleted_counts(conn, "alerts").items():
        counts[key] = counts.get(key, 0) + count
    metric = Metric("netwatch_alerts_total", "counter", "Alerts raised, by kind and severity.")
    for (kind, severity), count in sorted(counts.items()):
        metric.add(count, kind=kind, severity=severity)
    return metric


def _devices(conn: sqlite3.Connection) -> list[Metric]:
    devices = Metric(
        "netwatch_devices",
        "gauge",
        "Devices ever seen on the LAN; unknown ones have not been labelled or baselined.",
    )
    known = dict(conn.execute("SELECT known, count(*) FROM devices GROUP BY known").fetchall())
    devices.add(known.get(1, 0), state="known").add(known.get(0, 0), state="unknown")

    last_scan = Metric(
        "netwatch_discovery_last_scan_timestamp_seconds",
        "gauge",
        "When the last LAN scan finished.",
    )
    found = Metric(
        "netwatch_discovery_last_scan_devices",
        "gauge",
        "Devices that answered the last LAN scan.",
    )
    scan_us = storage.get_meta(conn, discovery.LAST_SCAN_KEY)
    if scan_us is not None:
        last_scan.add(int(scan_us) / 1_000_000)
        found.add(int(storage.get_meta(conn, discovery.LAST_FOUND_KEY) or 0))
    return [devices, last_scan, found]


def _blocklist(path: Path) -> list[Metric]:
    domains = Metric("netwatch_blocklist_domains", "gauge", "Domains in the installed blocklist.")
    generated = Metric(
        "netwatch_blocklist_generated_timestamp_seconds",
        "gauge",
        "When the installed blocklist was built.",
    )
    header = blocklist.read_header(path)
    if header is not None:
        if header.domains is not None:
            domains.add(header.domains)
        when = _timestamp(header.generated)
        if when is not None:
            generated.add(when)
    return [domains, generated]


def _counts(
    conn: sqlite3.Connection, table: str, column: str, known: Iterable[str]
) -> dict[tuple[str, ...], int]:
    """Rows stored plus rows deleted, per value of ``column``; known values start at 0."""
    counts: dict[tuple[str, ...], int] = {(value,): 0 for value in known}
    for value, count in conn.execute(f"SELECT {column}, count(*) FROM {table} GROUP BY {column}"):
        counts[(value,)] = counts.get((value,), 0) + count
    for key, count in storage.deleted_counts(conn, table).items():
        counts[key] = counts.get(key, 0) + count
    return counts


def _database_size(db_path: Path) -> int:
    total = 0
    for suffix in ("", "-wal"):
        with contextlib.suppress(FileNotFoundError):
            total += Path(f"{db_path}{suffix}").stat().st_size
    return total


def _timestamp(text: str | None) -> float | None:
    if not text:
        return None
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.timestamp()


def _labels(labels: Labels) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{name}="{_escape(value)}"' for name, value in labels)
    return "{" + inner + "}"


def _escape(value: str) -> str:
    # The text format escapes backslash, double quote and newline in label values. Values come
    # from the database, so anything else non-ASCII is replaced to keep the file ASCII.
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return escaped.encode("ascii", "replace").decode("ascii")


def _number(value: float) -> str:
    if float(value).is_integer() and abs(value) < 2**53:
        return str(int(value))
    return repr(float(value))


def run(settings: Settings, output: Path | None, environ: Mapping[str, str]) -> str:
    """Collect the metrics and write them to ``output``; returns the text."""
    db_path = settings.state_dir / DB_NAME
    conn = storage.connect_readonly(db_path)
    try:
        text = render(
            collect(conn, settings, db_path, datetime.now(UTC), revision=read_revision(environ))
        )
    finally:
        conn.close()
    if output is not None:
        write(output, text)
    return text
