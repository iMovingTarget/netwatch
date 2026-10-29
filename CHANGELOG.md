# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- LAN device discovery (Phase 3). `netwatch-discovery.service`, started every five minutes by
  `netwatch-discovery.timer`, sends an ARP request to every address in the IPv4 subnet of
  `NETWATCH_DISCOVERY_INTERFACE` (off when unset) and records every device that answers: MAC
  address, latest address, vendor from the IEEE registry (`ieee-data`), whether the address is
  locally administered, first and last seen. Networks larger than a /22 are refused.
- The first scan that finds anything is the baseline; after it, each MAC address seen for the
  first time raises one `new-device` alert (warning). Address history (which device held which
  address when) and new-device alerts are kept for `NETWATCH_DISCOVERY_RETENTION_DAYS` (90).
- Commands: `netwatch devices [--unknown]`, `netwatch devices label MAC NAME`,
  `netwatch devices scan [--from-file]`, and `examples/arp-scans.jsonl` to try them.
- `install.sh` installs `ieee-data` and runs the first scan when discovery is configured.
- CI scans a test LAN of network namespaces on a bridge, and installs a release without
  discovery to check the rollback path.

### Changed
- Database schema 4 (tables `devices` and `device_addresses`). An older release refuses the
  upgraded database; see `docs/rollback.md`.
- Alerts are stored by a module shared by every detector (`netwatch.alerts`).

## [0.3.0] - 2026-10-28

### Added
- Live SSH login monitoring (Phase 2). `netwatch-auth.service` follows sshd's journal (as `sshd`
  and `sshd-session`), stores every failed and successful login with its address, account,
  method and whether the account exists, and resumes after a restart without gaps; 90-day
  retention (`NETWATCH_AUTH_RETENTION_DAYS`).
- Alerts: `ssh-brute-force` (warning) when one address fails `NETWATCH_AUTH_MAX_FAILURES` (5)
  times within `NETWATCH_AUTH_WINDOW_MINUTES` (10), once per address per window, and
  `ssh-login-after-failures` (critical) for the first successful login from that address
  afterwards. Alerts are stored in a table later phases share and logged to the journal; the
  monitor reloads the current window from the database when it starts.
- Commands: `netwatch auth watch [--from-file]`, `netwatch auth recent`, `netwatch alerts`.
  Usernames, which clients choose, are escaped in the tables.
- `examples/sshd-journal.jsonl`: a real, anonymised sshd log from the VM.
- CI fails six SSH logins against the runner's sshd and checks the stored rows and the alert.

### Changed
- Depends on [log-analyzer](https://github.com/iMovingTarget/log-analyzer) 0.6.0 (installed
  from its git tag) for SSH parsing and rate tracking.
- Journal following moved from the DNS logger into `netwatch.journal`, shared by both services.

### Fixed
- `netwatch --version` from a shell shows the deployed revision; only the services did.

## [0.2.0] - 2026-10-28

### Added
- DNS logging and blocking (Phase 1). `install.sh` sets up dnsmasq on the address in
  `NETWATCH_DNS_LISTEN`, forwarding to `NETWATCH_DNS_UPSTREAMS` (default 1.1.1.1 and 9.9.9.9),
  and opens port 53 in ufw for `NETWATCH_DNS_ALLOW_FROM` only.
- `netwatch-dns.service` stores every query (time, client, name, type, status, answer, upstream)
  from dnsmasq's journal, resuming after a restart without losing or duplicating queries;
  30-day retention (`NETWATCH_DNS_RETENTION_DAYS`).
- `netwatch-blocklist.timer`: daily blocklist download (default StevenBlack unified hosts),
  allowlist in `/etc/netwatch/allowlist.txt`, sanity checks before replacing the current list.
- Commands: `netwatch dns recent`, `dns top`, `dns check`, `dns config`,
  `dns ingest [--from-file]`, `blocklist update`, `blocklist status`; `/usr/local/bin/netwatch`
  runs them as the `netwatch` user.
- `docs/rollback.md` and `examples/dnsmasq-journal.jsonl`.
- `deploy/check-host.sh` lists listening sockets, ufw's IPv6 setting and package states.

### Changed
- The state directory defaults to `/var/lib/netwatch`, and the CLI reads
  `/etc/netwatch/netwatch.env` itself, so commands work from a shell as well as under systemd.
- A dnsmasq drop-in (`DNSMASQ_EXCEPT=lo`) stops Ubuntu's dnsmasq start-up hook from registering
  127.0.0.1 as the host's resolver, which caused "Link lo is loopback device" warnings.

### Removed
- The Phase 0 placeholder service `netwatch-skeleton`; `install.sh` removes its unit.

### Fixed
- `check-host.sh` no longer prints a contradictory "DNSStubListener not set" line when
  `resolved.conf.d` is missing, and summarises long files instead of printing them in full.

## [0.1.0] - 2026-10-27

### Added
- `deploy/install.sh <ref>`: installs a tag, branch or commit as a hardened systemd service, with
  one virtualenv per commit, an atomic switch, removal of units a release no longer ships, and
  rollback by installing an older ref. `deploy/uninstall.sh` reverses it.
- `deploy/check-host.sh`: read-only report of what Netwatch depends on in a host.
- `netwatch-skeleton.service`: placeholder service that proves the deployment path (Phase 0).
- `netwatch --version`, including the deployed git revision.
- SQLite storage in WAL mode with schema versioning.
- Logging to the journal with syslog priorities.
- CI: ruff, pytest on Python 3.12 to 3.14 (Linux) and 3.14 (Windows), shellcheck, a unit
  hardening threshold, and an install, run and uninstall on a real systemd host.

[Unreleased]: https://github.com/iMovingTarget/netwatch/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/iMovingTarget/netwatch/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/iMovingTarget/netwatch/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/iMovingTarget/netwatch/releases/tag/v0.1.0
