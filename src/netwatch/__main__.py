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
    blocklist,
    dnsdb,
    dnsmasq,
    dnsprobe,
    ingest,
    logsetup,
    report,
    storage,
)
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
        raise NetwatchError(f"no database at {path} (is netwatch-dns running?)")
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
