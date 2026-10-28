# netwatch

A home-network security monitor that runs as a set of systemd services on a Linux host on the
LAN. It is built in phases: DNS logging and blocking, live detection of failed SSH logins, a LAN
device inventory with alerts for unknown devices, Telegram notifications, and a small read-only
dashboard. Each phase ships as a tagged release.

**Status: v0.3.0 (Phase 2, live SSH login monitor).** Netwatch follows sshd's log, stores every
failed and successful login, and raises an alert when one address keeps failing, and a critical
one if that address then gets in. Since Phase 1, dnsmasq answers DNS for the devices pointed at
the host and blocks ad, tracking and malware domains, and Netwatch stores every query.

From a test on the VM: six failed logins from the admin PC as unknown users, then a normal key
login from the same PC (address and account name replaced with documentation ones):

```
$ netwatch alerts
TIME                 SEVERITY  KIND                      MESSAGE
2026-10-28 17:04:45  warning   ssh-brute-force           5 or more failed SSH logins from 192.0.2.10 within 10 minutes (latest as 'nwdemo5')
2026-10-28 17:04:49  critical  ssh-login-after-failures  successful SSH login as 'alice' from 192.0.2.10 after a brute-force alert for it within 10 minutes
```

## What it does

| Phase | Release | What | Status |
|---|---|---|---|
| 0 | v0.1.0 | Install script, hardened units, CI install test, storage and logging base | done |
| 1 | v0.2.0 | DNS logger and sinkhole: dnsmasq answers, Netwatch logs every query and manages blocklists | done |
| 2 | v0.3.0 | Live failed-login detection for sshd, reusing [log-analyzer](https://github.com/iMovingTarget/log-analyzer) | done |
| 3 | v0.4.0 | Periodic ARP scan, device inventory, alert on unknown devices | planned |
| 4 | v0.5.0 | Telegram alerts with deduplication and cooldowns | planned |
| 5 | v0.6.0 | Read-only LAN-only dashboard behind a login | planned |

For DNS that means:

- **Forwarding:** names that aren't blocked go to the upstream servers (default 1.1.1.1 and
  9.9.9.9), with dnsmasq's cache in front.
- **Blocking:** names on the blocklist get `0.0.0.0` (A) and `::` (AAAA). The default list is
  [StevenBlack's unified hosts](https://github.com/StevenBlack/hosts) (about 76,000 domains);
  any https hosts-format or one-domain-per-line list works, and an allowlist overrides them.
- **Logging:** every query is stored for 30 days as forwarded, cached, blocked, local (answered by
  dnsmasq's own rules) or no-answer.

For SSH logins on the host:

- **Every login is stored** for 90 days: time, client address, account, failed or accepted, the
  method, and whether the account exists.
- **ssh-brute-force** (warning): 5 failed logins from one address within 10 minutes (both
  configurable). One alert per address per window, however long the attack goes on.
- **ssh-login-after-failures** (critical): a successful login from an address with a
  brute-force alert in the last window. One per brute-force alert.
- Alerts go to a table that later phases share; Phase 4 sends them to Telegram. Until then they
  are in `netwatch alerts` and in the journal at warning priority.

## Quick start (development)

Python 3.12 or newer. On Windows use `py` instead of `python3` and `set` for the variable.
`examples/dnsmasq-journal.jsonl` is real dnsmasq output (with documentation addresses), so this
works without dnsmasq:

```
git clone https://github.com/iMovingTarget/netwatch.git
cd netwatch
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
export NETWATCH_STATE_DIR=var
```

`examples/sshd-journal.jsonl` is a real sshd log from the VM, anonymised: eight failed logins from
one address in four seconds, between normal key logins.

```
$ netwatch auth watch --from-file examples/sshd-journal.jsonl
stored 12 new login events from examples/sshd-journal.jsonl, 1 alert
$ netwatch alerts
TIME                 SEVERITY  KIND             MESSAGE
2026-10-28 16:55:54  warning   ssh-brute-force  5 or more failed SSH logins from 203.0.113.5 within 10 minutes (latest as 'nwtest5')
$ netwatch auth recent -n 4
TIME                 SOURCE       RESULT    METHOD     USER
2026-10-28 16:55:55  203.0.113.5  failed    -          nwtest8 (no such user)
2026-10-28 16:56:17  192.0.2.10   accepted  publickey  alice
2026-10-28 16:56:17  192.0.2.10   accepted  publickey  alice
2026-10-28 16:56:25  192.0.2.10   accepted  publickey  alice
```

The DNS side works the same way with `examples/dnsmasq-journal.jsonl`:

```
$ netwatch dns ingest --from-file examples/dnsmasq-journal.jsonl
stored 17 new queries from examples/dnsmasq-journal.jsonl
$ netwatch dns recent -n 6
TIME                 CLIENT      TYPE  STATUS     NAME                       ANSWER
2026-10-28 11:47:51  192.0.2.11  PTR   local      20.1.168.192.in-addr.arpa  NXDOMAIN
2026-10-28 11:47:51  192.0.2.11  A     local      printer                    NXDOMAIN
2026-10-28 11:47:52  192.0.2.10  A     forwarded  example.org                192.0.2.81
2026-10-28 11:47:52  192.0.2.10  A     no-answer  host.dead.example          -
2026-10-28 11:47:55  192.0.2.10  A     forwarded  tracker.example.org        192.0.2.81
2026-10-28 11:47:57  192.0.2.11  A     forwarded  example.com                192.0.2.80
$ netwatch dns top -n 3 --hours 100000
Last 100000 h: 17 queries
  10 forwarded (58.8%), 2 cached (11.8%), 2 blocked (11.8%), 2 local (11.8%), 1 no-answer (5.9%)

Most blocked names:
        2  ads.example.com

Most queried names:
        4  example.com
        3  ads.example.com
        2  example.org

Busiest clients:
  queries  blocked  client
       10        2  192.0.2.10
        7        0  192.0.2.11
```

## Deploying to a host

Netwatch targets a systemd-based Linux host on the LAN (developed on Ubuntu Server 26.04).
`deploy/install.sh` takes a tag, branch or commit, so what runs on the host always matches a
commit:

```
git clone https://github.com/iMovingTarget/netwatch.git && cd netwatch
sudo deploy/check-host.sh > check.txt 2>&1   # optional: read-only report of the host
sudo deploy/install.sh v0.3.0                # first install: creates /etc/netwatch/netwatch.env
sudoedit /etc/netwatch/netwatch.env          # set NETWATCH_DNS_LISTEN and NETWATCH_DNS_ALLOW_FROM
sudo deploy/install.sh v0.3.0                # again, now with DNS
```

The second run, from CI's real install on a fresh Ubuntu runner (a documentation address stands in
for the LAN address):

```
install: setting up dnsmasq on 192.0.2.53
install: installing dnsmasq
install: downloading the first blocklist
192.0.2.53: example.com A -> NOERROR 104.20.23.154, 172.66.147.243 (4 ms)
192.0.2.53: 0.0.0.0.creative.hpyrdr.com A -> NOERROR 0.0.0.0 (blocked)
install: installed netwatch 0.1.0 (revision 1ca6f01f9788) from ci-under-test
install:   netwatch-dns.service: active
install:   netwatch-blocklist.timer: active
```

Then point one device's DNS at the host's LAN address and watch it with `netwatch dns recent`.
[docs/rollback.md](docs/rollback.md) describes how to switch a device back, stop DNS, roll back
to an older version or remove Netwatch. Installing an older ref is the version rollback;
`sudo deploy/uninstall.sh [--purge]` removes everything.

| Path | Contents |
|---|---|
| `/opt/netwatch/releases/<commit>/` | One virtualenv per installed commit, owned by root |
| `/opt/netwatch/current` | Symlink to the active release |
| `/etc/netwatch/netwatch.env` | Settings (and, later, secrets). `root:netwatch`, mode 0640 |
| `/etc/netwatch/allowlist.txt` | Names never to block |
| `/var/lib/netwatch/` | The SQLite database (DNS queries, SSH logins, alerts) |
| `/var/lib/netwatch-blocklist/` | The blocklist dnsmasq reads (world-readable) |
| `/etc/dnsmasq.d/netwatch.conf` | Generated by `netwatch dns config`; rewritten on every install |
| `/etc/systemd/system/` | `netwatch-*` units and `dnsmasq.service.d/netwatch.conf` |
| `/usr/local/bin/netwatch` | Runs the CLI as the `netwatch` user |

Day-to-day commands (they run as the `netwatch` user through `/usr/local/bin/netwatch`):

```
netwatch dns recent [-n 20] [--client ADDRESS] [--blocked]
netwatch dns top [--hours 24] [-n 10]
netwatch dns check                     # forwarding works and a listed name is blocked
netwatch blocklist status
netwatch blocklist update [--force]    # after editing the allowlist
netwatch auth recent [-n 20] [--source ADDRESS] [--failed]
netwatch alerts [-n 20]
journalctl -u 'netwatch*' -u dnsmasq
```

## How it works

```
 client --DNS--> dnsmasq (LAN address only) --forward--> 1.1.1.1 / 9.9.9.9
                   |  answers blocked names from /var/lib/netwatch-blocklist (inotify)
                   |  logs every query step to the journal (log-queries=extra)
                   v
 netwatch-dns: journalctl --follow -> assemble queries -> SQLite (+ resume cursor)
 netwatch-blocklist.timer (daily): download -> check -> atomic rename into the blocklist dir

 sshd / sshd-session --logs--> journal
 netwatch-auth: journalctl --follow -> log-analyzer SSHParser -> RateTracker per address
                -> logins + alerts -> SQLite (+ resume cursor)
```

| Module | Role |
|---|---|
| `netwatch/__main__.py` | `netwatch <command>` entry point; turns user-fixable errors into one-line messages |
| `netwatch/config.py` | Settings from environment variables and `/etc/netwatch/netwatch.env` |
| `netwatch/dnslog.py` | Groups dnsmasq's log lines by query serial number into one record per query |
| `netwatch/journal.py` | Runs `journalctl --follow` and drives a consumer: commit every second, prune hourly, resume cursor |
| `netwatch/ingest.py` | The `netwatch-dns` service: assembles queries and commits them with the cursor |
| `netwatch/dnsdb.py` | Stores and queries DNS records; idempotent inserts, retention |
| `netwatch/authlog.py` | SSH logins and alert rules on top of log-analyzer's parser and rate tracker |
| `netwatch/authwatch.py` | The `netwatch-auth` service: stores logins and alerts with the cursor, restores its window on start |
| `netwatch/authdb.py` | Stores and queries SSH logins and alerts |
| `netwatch/blocklist.py` | Downloads, parses, checks and atomically installs the blocklist |
| `netwatch/dnsmasq.py` | Generates dnsmasq's configuration |
| `netwatch/dnsprobe.py` | Minimal DNS client for `netwatch dns check` |
| `netwatch/report.py` | The terminal tables; text from outside (usernames) is escaped |
| `netwatch/storage.py` | SQLite in WAL mode, write transactions, schema versioning |
| `netwatch/logsetup.py` | Logging to stderr, with journald priorities when stderr is the journal |
| `deploy/` | Install, uninstall and host-check scripts, systemd units, example config |

Design decisions and their trade-offs:

- **dnsmasq answers, Netwatch observes.** A resolver written in Python would put Netwatch's own code
  in the path of every lookup. dnsmasq is small, packaged, and the engine Pi-hole is built on; Netwatch
  generates its configuration, feeds it the blocklist and reads its log. It listens on the LAN
  address only, so the host's own resolver (systemd-resolved) is untouched and the host keeps
  resolving names even if dnsmasq is stopped.
- **"Blocked" comes from dnsmasq, not from guessing.** With `log-queries=extra` each answer line
  names its source; an answer from the blocklist file is a block. Matching names against the list
  afterwards would disagree with dnsmasq whenever the list changed in between.
- **Lose nothing, store nothing twice.** dnsmasq writes several lines per query with no "done"
  marker, so queries are emitted once their answer has been quiet for a second. The resume cursor
  saved with each batch points at the oldest unfinished query, and reading from it again after a
  restart only re-reads queries the database ignores (`UNIQUE (ts_us, serial)`). CI stops the
  service, queries while it is down, restarts it and checks the query was stored.
- **Blocklist updates without root or restarts.** dnsmasq watches its `hostsdir` with inotify. The
  updater writes a dot-file (which dnsmasq ignores) and renames it into place, so dnsmasq never
  reads half a list. A list with fewer than 1,000 names or that lost more than half is refused: a
  blocklist host serving an error page must not switch blocking off.
- **Reuse log-analyzer, pinned.** SSH parsing and per-address rate counting come from
  log-analyzer, an earlier project by the same author, installed from its `v0.6.0` tag rather
  than copied. Feeding it this VM's real sshd log
  first exposed three bugs in it (a crafted username could frame another address, failures on
  key-only servers weren't counted, and some attempts counted twice); they were fixed there, with
  regression tests, in 0.6.0.
- **One alert per incident.** A brute-force alert has a cooldown of one window per address, and
  only the first login after it is critical; found when testing on the VM, where every later
  login from the admin PC raised another critical alert.
- **Restarts don't reset detection.** sshd lines are complete events, so `netwatch-auth` resumes
  after its saved cursor (the DNS logger resumes at it, because a query may be half-read). On start
  it reloads the last window's failures and alerts from the database, so an attack that straddles
  a restart is still caught and an alert isn't repeated.
- **Detect, don't block.** Netwatch alerts but changes no firewall rules. Automatic bans can be
  turned against you (lock out the admin, or the router), and OpenSSH 9.8 and later already slow
  down addresses that keep failing (`PerSourcePenalties`).
- **One package, one systemd unit per component.** Each service gets only what it needs: the
  loggers read the journal (`systemd-journal` group) with no network; the updater has the network
  but nothing else. `systemd-analyze security` rates them 0.6, 0.6 and 1.1; CI fails above 2.0.
- **Atomic, commit-pinned deploys.** Every install builds a virtualenv for one commit and only
  then switches the `current` symlink with `rename(2)`; installing an older ref is the rollback.
- **SQLite in WAL mode.** One host and a low write rate don't justify a database server. WAL lets
  the CLI read while the logger writes; writes take the lock up front (`BEGIN IMMEDIATE`).

## Limitations

- **Test devices only.** The host is a Hyper-V VM on a desktop PC, up only while the PC is on, so
  only devices pointed at it by hand use it; the router still hands out its own DNS. Whole-house
  DNS needs always-on hardware.
- **Encrypted DNS bypasses it.** A browser using DNS over HTTPS, Android's Private DNS set to a
  hostname, or iCloud Private Relay sends lookups past Netwatch, so they are neither logged nor
  blocked.
- **Blocking is by exact name and for A and AAAA only.** Subdomains not on the list are allowed,
  and other record types for a blocked name (for example HTTPS records) are still forwarded.
- **DNS blocking can't remove ads served from the same domains as content.** In a test with an
  iPhone, 16 of 240 lookups (about 7%) were blocked (Google and Apple ad and analytics domains), while
  Instagram's ads, which come from the same servers as its photos, were untouched. That is true
  of any DNS blocker, not just this one.
- **SSH monitoring covers this host's sshd only**, and the host is on the LAN, not reachable from
  the internet, so in practice it sees mistakes and tests rather than real attacks.
- **Attempts are counted from sshd's log.** A client that opens connections without sending a
  username leaves no "failed login" to count. Connections are told apart by address and port.
  Under a very large flood, journald's rate limit for sshd can drop lines.
- **Alerts aren't sent anywhere yet**; Telegram comes in Phase 4.
- **Privacy.** The database records which device looked up which name for 30 days, and SSH logins
  for 90. It is readable only by root and the `netwatch` user.
- **IPv4 listen address only** is configured; clients reaching the host over IPv6 aren't served.
- **One host.** Linux with systemd only; the Python code runs on Windows for development and
  tests, the services don't. `install.sh` needs access to GitHub and PyPI.

## Development

```
pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
shellcheck deploy/*.sh deploy/bin/netwatch
```

If dnsmasq is installed, the tests also start the real resolver with the generated configuration.
CI runs ruff, pytest on Python 3.12 to 3.14 on Linux (with dnsmasq) and 3.14 on Windows, and a
deploy job on a real systemd host: install with DNS, query through it, check the queries are
stored (including across a restart of the logger), fail six SSH logins against the runner's sshd
and check each is stored once with one alert, reinstall, and uninstall `--purge`.

AI-assisted implementation; architecture, operations and verification are human-owned.

## License

MIT. See [LICENSE](LICENSE).
