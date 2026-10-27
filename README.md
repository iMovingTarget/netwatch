# netwatch

A home-network security monitor that runs as a set of systemd services on a Linux host on the
LAN. It is built in phases: DNS logging and blocking, live detection of failed SSH logins, a LAN
device inventory with alerts for unknown devices, Telegram notifications, and a small read-only
dashboard. Each phase ships as a tagged release.

**Status: v0.1.0 (Phase 0, foundation).** No monitoring yet. This release is the deployment
pipeline every later phase builds on: an install script that deploys an exact git commit as a
hardened systemd service, an uninstall script, CI that runs that install on a real systemd host,
and a placeholder service that proves the whole path works.

Installing the Phase 0 branch on the VM (Ubuntu Server 26.04.1, systemd 259, Python 3.14), then
the service's journal across a reboot:

```
$ sudo deploy/install.sh phase-0-foundation
install: fetching phase-0-foundation from https://github.com/iMovingTarget/netwatch.git
install: resolved phase-0-foundation to 42a01d549cc5a3811a8692d6171945d698e07a5b
install: building /opt/netwatch/releases/42a01d549cc5a3811a8692d6171945d698e07a5b
install: smoke test: netwatch 0.1.0.dev0 (revision 42a01d549cc5)
install: creating system user netwatch
install: created /etc/netwatch/netwatch.env from the example
install: installed netwatch 0.1.0.dev0 (revision 42a01d549cc5) from phase-0-foundation
install:   netwatch-skeleton.service: active
install: logs: journalctl -u 'netwatch*' -n 50

$ journalctl -u netwatch-skeleton -o short-iso
22:07:18 systemd[1]: Started netwatch-skeleton.service - Netwatch walking skeleton (deploy pipeline check).
22:07:18 netwatch[2648]: netwatch.skeleton: started version=0.1.0.dev0 revision=42a01d549cc5a3811a8692d6171945d698e07a5b db=/var/lib/netwatch/netwatch.db
22:07:20 netwatch[2648]: netwatch.skeleton: stopped
22:07:20 systemd[1]: Stopping netwatch-skeleton.service - Netwatch walking skeleton (deploy pipeline check)...
22:07:21 systemd[1]: netwatch-skeleton.service: Deactivated successfully.
22:07:21 systemd[1]: Stopped netwatch-skeleton.service - Netwatch walking skeleton (deploy pipeline check).
-- Boot b587e4c4892f49d5a0e3e36cc8ea6891 --
22:07:28 systemd[1]: Started netwatch-skeleton.service - Netwatch walking skeleton (deploy pipeline check).
22:07:28 netwatch[1184]: netwatch.skeleton: started version=0.1.0.dev0 revision=42a01d549cc5a3811a8692d6171945d698e07a5b db=/var/lib/netwatch/netwatch.db
```

Timestamps are cut to the time of day and the hostname is removed; nothing else is edited. The
reboot shows the clean stop on SIGTERM and the automatic start on boot.

## What it does

| Phase | Release | What | Status |
|---|---|---|---|
| 0 | v0.1.0 | Install script, hardened unit, CI install test, storage and logging base | done |
| 1 | v0.2.0 | DNS logger and sinkhole: dnsmasq answers, Netwatch logs every query and manages blocklists | planned |
| 2 | v0.3.0 | Live failed-login detection for sshd, reusing [log-analyzer](https://github.com/iMovingTarget/log_analyzer) | planned |
| 3 | v0.4.0 | Periodic ARP scan, device inventory, alert on unknown devices | planned |
| 4 | v0.5.0 | Telegram alerts with deduplication and cooldowns | planned |
| 5 | v0.6.0 | Read-only LAN-only dashboard behind a login | planned |

## Quick start (development)

Python 3.12 or newer. On Windows use `py` instead of `python3`.

```
git clone https://github.com/iMovingTarget/netwatch.git
cd netwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

```
$ netwatch --version
netwatch 0.1.0
$ NETWATCH_STATE_DIR=var netwatch skeleton
22:11:41 INFO netwatch.skeleton: started version=0.1.0 revision=unknown db=var/netwatch.db
^C22:11:42 INFO netwatch.skeleton: stopped
```

## Deploying to a host

Netwatch targets a systemd-based Linux host on the LAN (developed on Ubuntu Server 26.04).
`deploy/install.sh` takes a tag, branch or commit, so what runs on the host always matches a
commit:

```
git clone https://github.com/iMovingTarget/netwatch.git && cd netwatch
sudo deploy/check-host.sh > check.txt 2>&1   # optional: read-only report of the host
sudo deploy/install.sh v0.1.0                # install or upgrade
sudo deploy/install.sh v0.0.9                # roll back: install the older ref
sudo deploy/uninstall.sh                     # remove services and code, keep config and data
sudo deploy/uninstall.sh --purge             # remove everything, including the netwatch user
```

| Path | Contents |
|---|---|
| `/opt/netwatch/releases/<commit>/` | One virtualenv per installed commit, owned by root |
| `/opt/netwatch/current` | Symlink to the active release |
| `/etc/netwatch/netwatch.env` | Settings and, in later phases, secrets. `root:netwatch`, mode 0640, never overwritten |
| `/var/lib/netwatch/` | State (SQLite database), created by systemd |
| `/etc/systemd/system/netwatch-*` | The units shipped in `deploy/systemd/` of the installed commit |

## How it works

| Module | Role |
|---|---|
| `netwatch/__main__.py` | `netwatch <command>` entry point; turns user-fixable errors into one-line messages |
| `netwatch/config.py` | Settings from environment variables (the systemd EnvironmentFile in production) |
| `netwatch/storage.py` | SQLite in WAL mode, write transactions, schema versioning |
| `netwatch/logsetup.py` | Logging to stderr, with journald priorities when stderr is the journal |
| `netwatch/skeleton.py` | Phase 0 placeholder service; replaced by the DNS service in Phase 1 |
| `deploy/` | Install, uninstall and host-check scripts, systemd units, example config |

Design decisions and their trade-offs:

- **One package, one systemd unit per component.** Each service gets only the privileges it needs
  (only the LAN scanner will get `CAP_NET_RAW`), restarts independently, and periodic jobs use
  systemd timers. The cost is more unit files; the services share state through SQLite.
- **Atomic, commit-pinned deploys.** Every install builds a new virtualenv for one commit and
  only then switches the `current` symlink with `rename(2)`. A failed download or build changes
  nothing, the previous release stays on disk, and installing an older ref is the rollback. Units
  that a release no longer ships are disabled and removed.
- **Sandboxed services.** The unit runs as the unprivileged `netwatch` user with no capabilities,
  a read-only filesystem apart from its state directory, no network, and a system call filter.
  `systemd-analyze security` rates it 0.4 ("SAFE"); CI fails if any unit rises above 2.0.
- **SQLite in WAL mode.** One host and a low write rate don't justify a database server. WAL lets
  the CLI and dashboard read while a service writes; write transactions take the lock up front
  (`BEGIN IMMEDIATE`) and wait up to 5 seconds for it instead of failing.
- **Configuration from the environment.** systemd supplies `STATE_DIRECTORY` and an
  EnvironmentFile; the code contains no paths, and tests override any setting.
- **Logs go to the journal.** No log files to rotate. Each line carries its syslog priority, so
  `journalctl -p warning` works. Priorities are only added when stderr really is the journal (the
  `JOURNAL_STREAM` device and inode match), because the variable is inherited by child processes.

## Limitations

- v0.1.0 monitors nothing; it only proves the deployment path.
- The development host is a Hyper-V VM on a desktop PC. It is only up while the PC is on, so only
  test devices use it for DNS. Whole-house DNS needs always-on hardware and is out of scope until
  then.
- Linux with systemd only. The Python code runs on Windows for development, but the services
  don't.
- `install.sh` needs internet access to GitHub and PyPI, and its start check only confirms a
  service is still running two seconds after start, which is not a health check.
- One host. There is no clustering or replication, and none is planned.

## Development

```
pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
shellcheck deploy/*.sh
```

CI runs ruff, pytest on Python 3.12 to 3.14 on Linux and 3.14 on Windows, and a deploy job that
lints the scripts, checks unit hardening, installs the commit under test with `install.sh` on a
real systemd host, and verifies the uninstall.

AI-assisted implementation; architecture, operations and verification are human-owned.

## License

MIT. See [LICENSE](LICENSE).
