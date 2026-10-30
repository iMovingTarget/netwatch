"""Command-line entry point: ``netwatch <command>``."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from pathlib import Path
from types import FrameType

from netwatch import (
    __version__,
    alerts,
    authdb,
    authwatch,
    blocklist,
    devicedb,
    discovery,
    dnsdb,
    dnsmasq,
    dnsprobe,
    ingest,
    logsetup,
    metrics,
    report,
    storage,
)
from netwatch.arp import normalize_mac
from netwatch.config import environ_with_env_file, load_settings, read_revision
from netwatch.errors import ConfigError, NetwatchError

Handler = Callable[[argparse.Namespace, Mapping[str, str]], int]


def version_string(environ: Mapping[str, str]) -> str:
    """The version, plus the git revision when the installer recorded one."""
    revision = read_revision(environ)
    if revision:
        return f"netwatch {__version__} (revision {revision[:12]})"
    return f"netwatch {__version__}"


def build_parser(environ: Mapping[str, str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="Home-network security monitor for a Linux host.",
    )
    parser.add_argument("--version", action="version", version=version_string(environ))
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    dns = commands.add_parser("dns", help="DNS logging and blocking").add_subparsers(
        dest="dns_command", metavar="<dns command>", required=True
    )
    ingest_cmd = dns.add_parser(
        "ingest",
        help="follow dnsmasq's query log and store every query (the netwatch-dns service)",
        description="Follow dnsmasq's journal and store every query until SIGTERM or SIGINT.",
    )
    ingest_cmd.add_argument(
        "--from-file",
        metavar="FILE",
        help="store the queries in a saved `journalctl -o json` export and exit",
    )
    ingest_cmd.set_defaults(handler=_run_ingest)
    config_cmd = dns.add_parser(
        "config",
        help="print the dnsmasq configuration for the current settings",
        description=f"Print the dnsmasq configuration that install.sh writes to"
        f" {dnsmasq.CONFIG_PATH}.",
    )
    config_cmd.set_defaults(handler=_dns_config)
    check_cmd = dns.add_parser(
        "check",
        help="query the resolver: forwarding works and a blocklisted name is blocked",
        description="Send test queries to the resolver. Without --name, also checks that the"
        " first name on the blocklist is answered with 0.0.0.0.",
    )
    check_cmd.add_argument("--server", help="resolver address (default: first NETWATCH_DNS_LISTEN)")
    check_cmd.add_argument("--port", type=int, default=53, help="resolver port (default: 53)")
    check_cmd.add_argument("--name", help="name to look up (default: example.com)")
    check_cmd.add_argument(
        "--type", choices=sorted(dnsprobe.QTYPES), default="A", help="record type (default: A)"
    )
    check_cmd.set_defaults(handler=_dns_check)
    recent_cmd = dns.add_parser("recent", help="show the most recent queries")
    recent_cmd.add_argument("-n", type=int, default=20, help="how many (default: 20)")
    recent_cmd.add_argument("--client", help="only queries from this client address")
    recent_cmd.add_argument("--blocked", action="store_true", help="only blocked queries")
    recent_cmd.set_defaults(handler=_dns_recent)
    top_cmd = dns.add_parser("top", help="summarise recent queries: counts, top names and clients")
    top_cmd.add_argument("--hours", type=int, default=24, help="time window (default: 24)")
    top_cmd.add_argument("-n", type=int, default=10, help="rows per list (default: 10)")
    top_cmd.set_defaults(handler=_dns_top)

    auth = commands.add_parser("auth", help="SSH login monitoring").add_subparsers(
        dest="auth_command", metavar="<auth command>", required=True
    )
    watch_cmd = auth.add_parser(
        "watch",
        help="follow sshd's log, store every login and raise alerts (the netwatch-auth service)",
        description="Follow sshd's journal and store every failed and successful login until"
        " SIGTERM or SIGINT, raising an alert on brute force.",
    )
    watch_cmd.add_argument(
        "--from-file",
        metavar="FILE",
        help="store the logins in a saved `journalctl -o json` export of sshd's log and exit",
    )
    watch_cmd.set_defaults(handler=_run_auth_watch)
    auth_recent_cmd = auth.add_parser("recent", help="show the most recent SSH logins")
    auth_recent_cmd.add_argument("-n", type=int, default=20, help="how many (default: 20)")
    auth_recent_cmd.add_argument("--source", help="only logins from this address")
    auth_recent_cmd.add_argument("--failed", action="store_true", help="only failed logins")
    auth_recent_cmd.set_defaults(handler=_auth_recent)

    devices_cmd = commands.add_parser(
        "devices",
        help="LAN device inventory from ARP scans",
        description="List every device the ARP scans have seen, by address, with its vendor and"
        " name. Without a command, lists; see the commands below for scanning and naming.",
    )
    devices_cmd.add_argument(
        "--unknown", action="store_true", help="only devices that appeared after the baseline"
    )
    devices_cmd.set_defaults(handler=_devices_list)
    devices_sub = devices_cmd.add_subparsers(dest="devices_command", metavar="<devices command>")
    scan_cmd = devices_sub.add_parser(
        "scan",
        help="scan the LAN once and record who answers (the netwatch-discovery service)",
        description="Send an ARP request to every address in the subnet of"
        " NETWATCH_DISCOVERY_INTERFACE and record who answers. Needs CAP_NET_RAW, which the"
        " netwatch-discovery service has: sudo systemctl start netwatch-discovery.service",
    )
    scan_cmd.add_argument(
        "--from-file",
        metavar="FILE",
        help="record scans saved as JSON lines instead of scanning (see examples/)",
    )
    scan_cmd.set_defaults(handler=_devices_scan)
    label_cmd = devices_sub.add_parser(
        "label",
        help="name a device and mark it known",
        description="Give a device a name, which also marks it as known.",
    )
    label_cmd.add_argument("mac", help="the device's MAC address, e.g. 00:00:5e:00:53:2a")
    label_cmd.add_argument("name", help="a name, e.g. 'living room TV'")
    label_cmd.set_defaults(handler=_devices_label)

    alerts_cmd = commands.add_parser("alerts", help="show the most recent alerts")
    alerts_cmd.add_argument("-n", type=int, default=20, help="how many (default: 20)")
    alerts_cmd.set_defaults(handler=_alerts)

    metrics_cmd = commands.add_parser(
        "metrics",
        help="write Prometheus metrics (the netwatch-metrics service)",
        description="Read the database and print Prometheus metrics, or write them to a file"
        " for node_exporter's textfile collector.",
    )
    metrics_cmd.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="replace FILE (a *.prom file) instead of printing to stdout",
    )
    metrics_cmd.set_defaults(handler=_metrics)

    bl = commands.add_parser("blocklist", help="manage the DNS blocklist").add_subparsers(
        dest="blocklist_command", metavar="<blocklist command>", required=True
    )
    update_cmd = bl.add_parser(
        "update",
        help="download the blocklists and install the result (the netwatch-blocklist service)",
        description="Download NETWATCH_BLOCKLIST_URLS, remove allowlisted names, check the"
        " result and swap it into place for dnsmasq.",
    )
    update_cmd.add_argument(
        "--force",
        action="store_true",
        help="install the result even if it is suspiciously small or shrank by more than half",
    )
    update_cmd.set_defaults(handler=_blocklist_update)
    status_cmd = bl.add_parser("status", help="show when the blocklist was updated and its size")
    status_cmd.set_defaults(handler=_blocklist_status)
    return parser


def _stop_on_signals() -> threading.Event:
    """An event that SIGTERM (systemd stop) and SIGINT (Ctrl+C) set."""
    stop = threading.Event()

    def request_stop(signum: int, frame: FrameType | None) -> None:
        # Only set the flag: logging from a signal handler can deadlock on the handler's lock.
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    return stop


def _run_ingest(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    settings = load_settings(environ)
    logsetup.configure(settings.log_level, environ)
    if args.from_file:
        added = ingest.import_file(settings, Path(args.from_file))
        print(f"stored {added} new queries from {args.from_file}")
        return 0
    return ingest.run(settings, _stop_on_signals())


def _run_auth_watch(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    settings = load_settings(environ)
    logsetup.configure(settings.log_level, environ)
    if args.from_file:
        added, alerts = authwatch.import_file(settings, Path(args.from_file))
        plural = "" if alerts == 1 else "s"
        print(f"stored {added} new login events from {args.from_file}, {alerts} alert{plural}")
        return 0
    return authwatch.run(settings, _stop_on_signals())


def _dns_config(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    print(dnsmasq.render_config(load_settings(environ)), end="")
    return 0


def _dns_check(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    settings = load_settings(environ)
    server = args.server or (settings.dns_listen[0] if settings.dns_listen else None)
    if server is None:
        raise ConfigError("no resolver to check: pass --server or set NETWATCH_DNS_LISTEN")
    ok = True
    name = args.name or "example.com"
    reply = dnsprobe.query(server, name, args.type, port=args.port)
    answers = ", ".join(reply.answers) or "no records"
    print(f"{server}: {name} {args.type} -> {reply.rcode} {answers} ({reply.elapsed_ms:.0f} ms)")
    if reply.rcode not in ("NOERROR", "NXDOMAIN"):
        ok = False
    if args.name is None:
        blocked = blocklist.first_domain(settings.blocklist_dir / blocklist.HOSTS_FILE)
        if blocked is None:
            print("no blocklist yet, so blocking was not checked")
        else:
            reply = dnsprobe.query(server, blocked, "A", port=args.port)
            is_blocked = reply.answers == ("0.0.0.0",)
            verdict = "blocked" if is_blocked else "NOT BLOCKED"
            print(
                f"{server}: {blocked} A -> {reply.rcode} {', '.join(reply.answers) or 'no records'}"
                f" ({verdict})"
            )
            ok = ok and is_blocked
    return 0 if ok else 1


def _open_db(environ: Mapping[str, str]) -> closing[storage.sqlite3.Connection]:
    settings = load_settings(environ)
    path = settings.state_dir / ingest.DB_NAME
    if not path.exists():
        raise NetwatchError(f"no database at {path} (is a netwatch service running?)")
    return closing(storage.connect(path))


def _dns_recent(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    with _open_db(environ) as conn:
        queries = dnsdb.recent(conn, args.n, client=args.client, blocked_only=args.blocked)
    print(report.recent_table(queries), end="")
    return 0


def _dns_top(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    since_us = time.time_ns() // 1000 - args.hours * 3_600_000_000
    with _open_db(environ) as conn:
        print(report.summary(conn, since_us, args.hours, args.n), end="")
    return 0


def _auth_recent(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    with _open_db(environ) as conn:
        events = authdb.recent(conn, args.n, source=args.source, failed_only=args.failed)
    print(report.auth_table(events), end="")
    return 0


def _alerts(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    with _open_db(environ) as conn:
        stored = alerts.recent(conn, args.n)
    print(report.alerts_table(stored), end="")
    return 0


def _devices_list(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    with _open_db(environ) as conn:
        found = devicedb.devices(conn, unknown_only=args.unknown)
        last_scan = storage.get_meta(conn, discovery.LAST_SCAN_KEY)
    if args.unknown and not found:
        print("no unknown devices")
        return 0
    last_scan_us = None if last_scan is None else int(last_scan)
    print(report.devices_table(found, last_scan_us, count_present=not args.unknown), end="")
    return 0


def _devices_scan(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    settings = load_settings(environ)
    logsetup.configure(settings.log_level, environ)
    if args.from_file:
        results = discovery.import_file(settings, Path(args.from_file))
        raised = sum(len(r.alerts) for r in results)
        print(f"recorded {len(results)} scans from {args.from_file}, {raised} new-device alerts")
        return 0
    discovery.run(settings)
    return 0


LABEL_MAX = 64


def _devices_label(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    try:
        mac = normalize_mac(args.mac)
    except ValueError as exc:
        raise ConfigError(str(exc)) from None
    name = args.name.strip()
    if not name or len(name) > LABEL_MAX or not name.isprintable():
        raise ConfigError(f"a device name must be 1 to {LABEL_MAX} printable characters")
    with _open_db(environ) as conn, storage.transaction(conn):
        if not devicedb.set_label(conn, mac, name):
            raise NetwatchError(f"no device with MAC address {mac} (see: netwatch devices)")
    print(f"{mac} is now known as {name!r}")
    return 0


def _metrics(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    text = metrics.run(load_settings(environ), args.output, environ)
    if args.output is None:
        sys.stdout.write(text)
    return 0


def _blocklist_update(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    settings = load_settings(environ)
    logsetup.configure(settings.log_level, environ)
    result = blocklist.update(settings, force=args.force)
    was = f" (was {result.previous})" if result.previous is not None else ""
    print(f"blocklist: {result.domains} domains{was}, {result.allowed} allowlisted")
    return 0


def _blocklist_status(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    settings = load_settings(environ)
    path = settings.blocklist_dir / blocklist.HOSTS_FILE
    header = blocklist.read_header(path)
    if header is None:
        print(f"no blocklist at {path} (run: netwatch blocklist update)", file=sys.stderr)
        return 1
    print(f"file:      {path}")
    print(f"generated: {header.generated or 'unknown'}")
    print(f"domains:   {header.domains if header.domains is not None else 'unknown'}")
    for source in header.sources:
        print(f"source:    {source}")
    return 0


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    """Run a command. ``environ`` replaces the real environment and settings file (for tests)."""
    try:
        env = environ_with_env_file(os.environ) if environ is None else environ
    except NetwatchError as exc:
        print(f"netwatch: {exc}", file=sys.stderr)
        return exc.exit_code
    parser = build_parser(env)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_usage(sys.stderr)
        print("netwatch: error: a command is required (see netwatch --help)", file=sys.stderr)
        return 2
    handler: Handler = args.handler
    try:
        return handler(args, env)
    except NetwatchError as exc:
        print(f"netwatch: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
