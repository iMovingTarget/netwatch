from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netwatch import alerts, authdb, dnsdb, metrics, storage
from netwatch.__main__ import main
from netwatch.alerts import Alert
from netwatch.authlog import AuthEvent
from netwatch.config import load_settings
from netwatch.dnslog import DnsQuery
from netwatch.errors import StorageError

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
# A sample line: name, optional {labels}, value. Label values may hold escaped characters.
SAMPLE = re.compile(r'^[a-z_]+(\{[a-z_]+="(?:[^"\\]|\\.)*"(,[a-z_]+="(?:[^"\\]|\\.)*")*\})? \S+$')


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {
        "NETWATCH_STATE_DIR": str(tmp_path),
        "NETWATCH_BLOCKLIST_DIR": str(tmp_path / "blocklist"),
    }


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / "netwatch.db")) as c:
        yield c


def _query(n: int, status: str = "forwarded") -> DnsQuery:
    return DnsQuery(
        ts_us=n * 1_000_000,
        serial=n,
        client="192.0.2.10",
        name="example.com",
        qtype="A",
        status=status,
        answer="198.51.100.1",
        upstream="203.0.113.53",
    )


def _login(n: int, outcome: str = "failed") -> AuthEvent:
    return AuthEvent(
        ts_us=n * 1_000_000,
        source="203.0.113.5",
        username="root",
        outcome=outcome,
        method=None,
        invalid_user=False,
        message="m",
        cursor=f"c{n}",
    )


def _collect(conn: sqlite3.Connection, env: dict[str, str]) -> dict[str, float]:
    """The samples as {'name{labels}': value}."""
    text = metrics.render(
        metrics.collect(conn, load_settings(env), Path(env["NETWATCH_STATE_DIR"]) / "x.db", NOW)
    )
    samples = {}
    for line in text.splitlines():
        if not line.startswith("#"):
            key, value = line.rsplit(" ", 1)
            samples[key] = float(value)
    return samples


def test_render_writes_help_type_and_escaped_labels() -> None:
    metric = metrics.Metric("nw_things_total", "counter", "Things.").add(3, kind='a"b\\c\nd')
    empty = metrics.Metric("nw_nothing", "gauge", "Skipped: no samples.")
    assert metrics.render([metric, empty]) == (
        "# HELP nw_things_total Things.\n"
        "# TYPE nw_things_total counter\n"
        'nw_things_total{kind="a\\"b\\\\c\\nd"} 3\n'
    )


def test_render_keeps_fractions_and_whole_numbers_apart() -> None:
    metric = metrics.Metric("nw_t", "gauge", "T.").add(1761825600.5).add(42.0, x="y")
    assert metrics.render([metric]).splitlines()[2:] == ["nw_t 1761825600.5", 'nw_t{x="y"} 42']


def test_empty_database_has_every_known_series_at_zero(
    conn: sqlite3.Connection, env: dict[str, str]
) -> None:
    samples = _collect(conn, env)
    for status in metrics.DNS_STATUSES:
        assert samples[f'netwatch_dns_queries_total{{status="{status}"}}'] == 0
    assert samples['netwatch_ssh_logins_total{outcome="failed"}'] == 0
    assert samples['netwatch_alerts_total{kind="new-device",severity="warning"}'] == 0
    assert samples['netwatch_devices{state="unknown"}'] == 0
    assert samples["netwatch_metrics_generated_timestamp_seconds"] == NOW.timestamp()
    # Nothing has happened yet, so there is no "last" time to report.
    assert not any(k.startswith("netwatch_dns_last_query") for k in samples)
    assert not any(k.startswith("netwatch_discovery_last_scan") for k in samples)
    assert not any(k.startswith("netwatch_blocklist") for k in samples)


def test_counters_do_not_drop_when_retention_deletes_rows(
    conn: sqlite3.Connection, env: dict[str, str]
) -> None:
    # Regression: counters were row counts, which fell when old rows were pruned.
    with storage.transaction(conn):
        dnsdb.store(conn, [_query(1), _query(2, "blocked"), _query(3)])
        authdb.store_events(conn, [_login(1), _login(5, "accepted")])
        alerts.store(conn, [Alert(1_000_000, "ssh-brute-force", "warning", "203.0.113.5", "m")])
    before = _collect(conn, env)
    with storage.transaction(conn):
        dnsdb.prune(conn, 10_000_000)
        authdb.prune(conn, 10_000_000)
        alerts.prune(conn, 10_000_000, ["ssh-brute-force"])
    with storage.transaction(conn):
        dnsdb.store(conn, [_query(20)])
    after = _collect(conn, env)

    assert before['netwatch_dns_queries_total{status="forwarded"}'] == 2
    assert after['netwatch_dns_queries_total{status="forwarded"}'] == 3
    assert after['netwatch_dns_queries_total{status="blocked"}'] == 1
    assert after['netwatch_ssh_logins_total{outcome="accepted"}'] == 1
    assert after['netwatch_alerts_total{kind="ssh-brute-force",severity="warning"}'] == 1
    assert after["netwatch_dns_last_query_timestamp_seconds"] == 20


def test_devices_and_last_scan(conn: sqlite3.Connection, env: dict[str, str]) -> None:
    with storage.transaction(conn):
        conn.executemany(
            "INSERT INTO devices (mac, vendor, local_admin, label, known, first_seen_us,"
            " last_seen_us, last_ip) VALUES (?, NULL, 0, NULL, ?, 1, 1, '192.0.2.1')",
            [("00:00:5e:00:53:01", 1), ("00:00:5e:00:53:02", 1), ("00:00:5e:00:53:03", 0)],
        )
        storage.put_meta(conn, "discovery.last_scan_us", "1761825600000000")
        storage.put_meta(conn, "discovery.last_scan_devices", "2")
    samples = _collect(conn, env)
    assert samples['netwatch_devices{state="known"}'] == 2
    assert samples['netwatch_devices{state="unknown"}'] == 1
    assert samples["netwatch_discovery_last_scan_timestamp_seconds"] == 1761825600
    assert samples["netwatch_discovery_last_scan_devices"] == 2


def test_heartbeats_of_the_journal_followers(conn: sqlite3.Connection, env: dict[str, str]) -> None:
    storage.set_meta(conn, "dns.heartbeat_us", "1761825600000000")
    samples = _collect(conn, env)
    assert samples['netwatch_heartbeat_timestamp_seconds{component="dns"}'] == 1761825600
    # No heartbeat yet from netwatch-auth: no sample rather than a misleading 0.
    assert 'netwatch_heartbeat_timestamp_seconds{component="auth"}' not in samples


def test_blocklist_size_and_age_come_from_its_header(
    conn: sqlite3.Connection, env: dict[str, str], tmp_path: Path
) -> None:
    (tmp_path / "blocklist").mkdir()
    (tmp_path / "blocklist" / "blocklist.hosts").write_text(
        "# Netwatch blocklist, generated 2026-10-30T00:56:12+00:00\n"
        "# source: https://example.com/hosts\n"
        "# domains: 2\n"
        "0.0.0.0 ads.example\n:: ads.example\n0.0.0.0 track.example\n:: track.example\n"
    )
    samples = _collect(conn, env)
    assert samples["netwatch_blocklist_domains"] == 2
    generated = datetime(2026, 10, 30, 0, 56, 12, tzinfo=UTC).timestamp()
    assert samples["netwatch_blocklist_generated_timestamp_seconds"] == generated


def test_every_line_is_valid_exposition_format(
    conn: sqlite3.Connection, env: dict[str, str]
) -> None:
    text = metrics.run(load_settings(env), None, {**env, "NETWATCH_REVISION": "e461766a88e1ff"})
    assert text.isascii()
    assert 'netwatch_build_info{version="' in text and 'revision="e461766a88e1"} 1' in text
    for line in text.splitlines():
        assert line.startswith(("# HELP ", "# TYPE ")) or SAMPLE.match(line), line


def test_readonly_open_refuses_another_schema_and_changes_nothing(tmp_path: Path) -> None:
    db = tmp_path / "netwatch.db"
    with closing(sqlite3.connect(db)) as raw:
        raw.execute("PRAGMA user_version = 3")
    with pytest.raises(StorageError, match="schema version 3; this Netwatch reads version"):
        storage.connect_readonly(db)
    with closing(sqlite3.connect(db)) as raw:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == 3


def test_readonly_connection_cannot_write(conn: sqlite3.Connection, tmp_path: Path) -> None:
    ro = storage.connect_readonly(tmp_path / "netwatch.db")
    with closing(ro), pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro.execute("INSERT INTO meta VALUES ('k', 'v')")


def test_cli_writes_the_file_in_one_step(
    conn: sqlite3.Connection, env: dict[str, str], tmp_path: Path
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert main(["metrics", "--output", str(out / "netwatch.prom")], environ=env) == 0
    assert [p.name for p in out.iterdir()] == ["netwatch.prom"]
    assert (out / "netwatch.prom").stat().st_mode & 0o777 == 0o644
    assert "netwatch_dns_queries_total" in (out / "netwatch.prom").read_text()


def test_cli_prints_to_stdout(
    conn: sqlite3.Connection, env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["metrics"], environ=env) == 0
    assert "# TYPE netwatch_dns_queries_total counter" in capsys.readouterr().out


def test_cli_without_a_database_is_one_line_error(
    env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["metrics"], environ=env) == 1
    err = capsys.readouterr().err
    assert err.startswith("netwatch: cannot open database") and err.count("\n") == 1


def test_cli_unwritable_output_is_one_line_error(
    conn: sqlite3.Connection,
    env: dict[str, str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["metrics", "--output", str(tmp_path / "missing" / "n.prom")], environ=env) == 1
    assert capsys.readouterr().err.startswith("netwatch: cannot write")
