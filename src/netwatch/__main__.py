"""Command-line entry point: ``netwatch <command>``."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from types import FrameType

from netwatch import __version__, blocklist, ingest, logsetup, skeleton
from netwatch.config import environ_with_env_file, load_settings, read_revision
from netwatch.errors import NetwatchError

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

    skeleton_cmd = commands.add_parser(
        "skeleton",
        help="run the Phase 0 placeholder service until SIGTERM or SIGINT",
        description="Placeholder service that proves the deploy pipeline (replaced in Phase 1).",
    )
    skeleton_cmd.set_defaults(handler=_run_skeleton)

    dns = commands.add_parser("dns", help="DNS logging and blocking").add_subparsers(
        dest="dns_command", metavar="<dns command>", required=True
    )
    ingest_cmd = dns.add_parser(
        "ingest",
        help="follow dnsmasq's query log and store every query (the netwatch-dns service)",
        description="Follow dnsmasq's journal and store every query until SIGTERM or SIGINT.",
    )
    ingest_cmd.set_defaults(handler=_run_ingest)

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


def _run_skeleton(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    settings = load_settings(environ)
    logsetup.configure(settings.log_level, environ)
    return skeleton.run(settings, _stop_on_signals())


def _run_ingest(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    settings = load_settings(environ)
    logsetup.configure(settings.log_level, environ)
    return ingest.run(settings, _stop_on_signals())


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
