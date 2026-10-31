# netwatch

A home-network security monitor that runs as a set of systemd services on a Linux host on the
LAN. It is built in phases: DNS logging and blocking, live detection of failed SSH logins, a LAN
device inventory with alerts for unknown devices, metrics and dashboards in Prometheus and
Grafana, and Telegram notifications. Each phase ships as a tagged release.

**Status: v0.5.0 (Phase 4, Prometheus metrics and Grafana).** The host exports its numbers and
its own health to Prometheus through node_exporter, and a second host runs Prometheus and Grafana
with health alerts and two dashboards ([docs/monitoring.md](docs/monitoring.md)). Since Phase 3
Netwatch scans the LAN by ARP every five minutes and alerts on an unknown device; since Phase 2
it follows sshd's log and alerts on failed-login attacks; and since Phase 1 dnsmasq answers and
blocks DNS for the devices pointed at the host, with every query stored.

From the VM: discovery was switched on with the router and the admin PC online. The owner's
phone was asleep and missed that first scan, so an hour later, when it was in use, it was
reported as new. Its Wi-Fi address was checked in the phone's settings, and it was labelled
(addresses replaced with documentation ones):

```
$ netwatch alerts -n 1
TIME                 SEVERITY  KIND        MESSAGE
2026-10-29 18:34:10  warning   new-device  new device 02:00:5e:00:53:61 at 192.0.2.101 (locally administered address, so no vendor; phones use these as private Wi-Fi addresses)
$ netwatch devices label 02:00:5e:00:53:61 iPhone
02:00:5e:00:53:61 is now known as 'iPhone'
$ netwatch devices --unknown
no unknown devices
```

## What it does

| Phase | Release | What | Status |
|---|---|---|---|
| 0 | v0.1.0 | Install script, hardened units, CI install test, storage and logging base | done |
| 1 | v0.2.0 | DNS logger and sinkhole: dnsmasq answers, Netwatch logs every query and manages blocklists | done |
| 2 | v0.3.0 | Live failed-login detection for sshd, reusing [log-analyzer](https://github.com/iMovingTarget/log-analyzer) | done |
| 3 | v0.4.0 | Periodic ARP scan, device inventory with vendors, alert on unknown devices | done |
| 4 | v0.5.0 | Prometheus metrics and Grafana dashboards (on a separate monitoring VM), health alerts | done |
| 5 | v0.6.0 | Telegram alerts with deduplication and cooldowns | planned |

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
- Alerts go to a table every detector shares; Phase 5 sends them to Telegram. Until then they
  are in `netwatch alerts` and in the journal at warning priority.

For the devices on the LAN (opt-in: set `NETWATCH_DISCOVERY_INTERFACE`, for example `eth0`):

- **Every device that answers ARP is recorded**: MAC address, latest IPv4 address, vendor from
  the IEEE registry (or "locally administered" for a phone's private Wi-Fi address), first and
  last seen, and an optional label. The scan runs every five minutes and takes about four
  seconds for a /24.
- **The first scan is the baseline**: the devices on the network when discovery is switched on
  are recorded as known, without alerts.
- **new-device** (warning): a MAC address seen for the first time after the baseline. One alert
  per address, ever; it stays "new" in `netwatch devices --unknown` until it is labelled.
- **Address history**: which device held which address and when, kept for 90 days, so a DNS
  client address can be traced to a device even after its lease changed.

For metrics and dashboards (opt-in: set `NETWATCH_METRICS_LISTEN`):

- **`netwatch metrics`** writes the DNS, login, alert and device numbers, each component's
  heartbeat, the blocklist and database sizes and the running version in the Prometheus text
  format. A timer writes it every minute; node_exporter serves it alongside the host's own
  metrics and the systemd state of Netwatch's units. Netwatch never listens on the network for
  this. The counters survive retention, and no domain, address or MAC becomes a metric label.
- **A separate monitoring host** runs Prometheus and Grafana in Docker, with eleven health alerts
  (host or a service down, a stalled follower, stale metrics, scans or blocklist, a filling disk)
  and two dashboards. It is built from a tag like the Netwatch host is. See
  [docs/monitoring.md](docs/monitoring.md).

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

`examples/arp-scans.jsonl` holds four saved scans with documentation addresses, modelled on the
VM test: a baseline of a router, a PC and a phone, then a visitor's phone (with a private Wi-Fi
address) joins, then the phone switches its private address off and comes back with its real
one. Point `NETWATCH_OUI_DIR` at the small registry in the test fixtures so vendors resolve on any
OS (on Ubuntu the full one is in `/usr/share/ieee-data`, package `ieee-data`):

```
$ export NETWATCH_OUI_DIR=tests/fixtures/ieee-data
$ netwatch devices scan --from-file examples/arp-scans.jsonl
recorded 4 scans from examples/arp-scans.jsonl, 2 new-device alerts
$ netwatch devices
last scan 2026-10-29 17:15:04: 4 of 5 devices answered
IP           MAC                FIRST SEEN           LAST SEEN            STATUS  NAME
192.0.2.1    00:00:5e:00:53:01  2026-10-29 17:00:03  2026-10-29 17:15:04  known   [ICANN, IANA Department]
192.0.2.97   02:00:5e:00:53:61  2026-10-29 17:00:03  2026-10-29 17:10:03  known   [locally administered]
192.0.2.99   00:00:5e:00:53:63  2026-10-29 17:00:03  2026-10-29 17:15:04  known   [ICANN, IANA Department]
192.0.2.100  00:00:5e:00:53:64  2026-10-29 17:15:04  2026-10-29 17:15:04  new     [ICANN, IANA Department]
192.0.2.120  06:00:5e:00:53:78  2026-10-29 17:10:03  2026-10-29 17:15:04  new     [locally administered]
$ netwatch alerts
TIME                 SEVERITY  KIND        MESSAGE
2026-10-29 17:10:03  warning   new-device  new device 06:00:5e:00:53:78 at 192.0.2.120 (locally administered address, so no vendor; phones use these as private Wi-Fi addresses)
2026-10-29 17:15:04  warning   new-device  new device 00:00:5e:00:53:64 at 192.0.2.100 (ICANN, IANA Department)
$ netwatch devices label 06:00:5e:00:53:78 "visitor's phone"
06:00:5e:00:53:78 is now known as "visitor's phone"
```

The documentation MAC addresses (RFC 7042) all belong to IANA's block, hence the vendor. The
times are UTC here; the CLI prints local time.

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
sudo deploy/install.sh v0.5.0                # first install: creates /etc/netwatch/netwatch.env
sudoedit /etc/netwatch/netwatch.env          # set NETWATCH_DNS_LISTEN, NETWATCH_DNS_ALLOW_FROM,
                                             # NETWATCH_DISCOVERY_INTERFACE and, for Phase 4,
                                             # NETWATCH_METRICS_LISTEN / NETWATCH_METRICS_ALLOW_FROM
sudo deploy/install.sh v0.5.0                # again, now with DNS, discovery and metrics
```

The second run on the VM, upgrading from v0.3.0 to the release candidate (the LAN address
replaced with a documentation one). The first scan records what is on the LAN as the baseline:

```
install: keeping the existing /etc/netwatch/netwatch.env
install: setting up dnsmasq on 192.0.2.53
install: ufw: allowed DNS from 192.0.2.0/24 to 192.0.2.53
192.0.2.53: example.com A -> NOERROR 172.66.147.243, 104.20.23.154 (44 ms)
192.0.2.53: 0.0.0.0.creative.hpyrdr.com A -> NOERROR 0.0.0.0 (blocked)
install: scanning the LAN on eth0
install: last scan 2026-10-29 17:38:41: 2 of 2 devices answered
install: installed netwatch 0.4.0 (revision 658fa0dfdc32) from phase-3-discovery
install:   netwatch-auth.service: active
install:   netwatch-dns.service: active
install:   netwatch-blocklist.timer: active
install:   netwatch-discovery.timer: active
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
| `/var/lib/netwatch/` | The SQLite database (DNS queries, SSH logins, devices, alerts) |
| `/var/lib/netwatch-blocklist/` | The blocklist dnsmasq reads (world-readable) |
| `/etc/dnsmasq.d/netwatch.conf` | Generated by `netwatch dns config`; rewritten on every install |
| `/etc/systemd/system/` | `netwatch-*` units and `dnsmasq.service.d/netwatch.conf` |
| `/usr/local/bin/netwatch` | Runs the CLI as the `netwatch` user |
| `/usr/share/ieee-data/` | The IEEE MAC address registry (package `ieee-data`), for vendors |
| `/var/lib/netwatch-metrics/` | The Prometheus file node_exporter serves (world-readable) |
| `.../prometheus-node-exporter.service.d/netwatch.conf` | node_exporter's listen address and collectors |

Day-to-day commands (they run as the `netwatch` user through `/usr/local/bin/netwatch`):

```
netwatch dns recent [-n 20] [--client ADDRESS] [--blocked]
netwatch dns top [--hours 24] [-n 10]
netwatch dns check                     # forwarding works and a listed name is blocked
netwatch blocklist status
netwatch blocklist update [--force]    # after editing the allowlist
netwatch auth recent [-n 20] [--source ADDRESS] [--failed]
netwatch devices [--unknown]           # the inventory; --unknown: new since the baseline
netwatch devices label MAC NAME        # name a device; it is then known
netwatch alerts [-n 20]
netwatch metrics [--output FILE]       # Prometheus metrics (the netwatch-metrics timer writes them)
sudo systemctl start netwatch-discovery.service   # scan now instead of within five minutes
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

 netwatch-discovery.timer (every 5 min) -> netwatch-discovery (CAP_NET_RAW only):
     ARP request to every address in eth0's subnet -> replies -> vendor (IEEE registry)
     -> devices + address history + new-device alerts -> SQLite

 netwatch-metrics.timer (every minute) -> netwatch metrics (read-only DB, no network):
     database -> Prometheus text file -> node_exporter (LAN address) <--scrape-- Prometheus -> Grafana
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
| `netwatch/authdb.py` | Stores and queries SSH logins |
| `netwatch/alerts.py` | The alerts table every detector writes to |
| `netwatch/arp.py` | Builds and parses ARP frames (RFC 826); MAC address helpers |
| `netwatch/scanner.py` | The ARP sweep over a packet socket; reads the interface's address |
| `netwatch/oui.py` | Vendor lookup in the IEEE registry, longest prefix first |
| `netwatch/discovery.py` | The `netwatch-discovery` service: baseline, new-device alerts, retention |
| `netwatch/devicedb.py` | Stores and queries devices and which address each held when |
| `netwatch/blocklist.py` | Downloads, parses, checks and atomically installs the blocklist |
| `netwatch/dnsmasq.py` | Generates dnsmasq's configuration |
| `netwatch/dnsprobe.py` | Minimal DNS client for `netwatch dns check` |
| `netwatch/report.py` | The terminal tables; text from outside (usernames) is escaped |
| `netwatch/metrics.py` | Reads the database (read-only) and renders Prometheus metrics for `netwatch metrics` |
| `netwatch/storage.py` | SQLite in WAL mode, write transactions, schema versioning |
| `netwatch/logsetup.py` | Logging to stderr, with journald priorities when stderr is the journal |
| `deploy/` | Install, uninstall and host-check scripts, systemd units, example config |
| `monitoring/` | Prometheus and Grafana for a separate host: Compose, scrape config, alert rules and tests, provisioned dashboards, `setup.sh` |

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
- **Ask every address instead of listening.** The kernel's neighbour table only knows devices the
  host has talked to (on the VM: the router and the admin PC), and listening for broadcasts only
  finds devices that choose to announce themselves. Every IPv4 device on the LAN has to answer
  ARP for its own address, so a sweep finds them whether or not they want to be found. A second
  pass asks the silent addresses again, because a phone in Wi-Fi power save often misses the
  first request.
- **A baseline, not an allowlist.** Alerting on every device on install day is noise, and an
  allowlist file is upkeep nobody keeps up. Whatever is there when discovery is switched on is
  known; anything after that alerts once and stays "new" until it is labelled. A scan that finds
  nothing (not even the router) means the scan failed, so it never becomes the baseline.
- **One alert per MAC address, ever.** A laptop that sleeps through a scan isn't new when it
  comes back. A phone that switches to a different private Wi-Fi address is a new address, so it
  alerts, and the message says it's locally administered, which is usually exactly that.
- **Vendors from the IEEE registry, longest prefix first.** Ubuntu packages the registry
  (`ieee-data`), so there's nothing to download or call. IEEE sells 28- and 36-bit blocks inside
  its own 24-bit ones, so matching only the first 24 bits would name "IEEE Registration
  Authority" for many small manufacturers.
- **Raw frames with one capability.** The scan is about 150 lines of standard-library Python on
  an `AF_PACKET` socket rather than a call to `arp-scan`, so it needs no extra package and only
  `CAP_NET_RAW`. Its unit has no other capability, cannot open IP connections
  (`IPAddressDeny=any`) and writes only the state directory.
- **Address history, not just the latest address.** DNS queries are stored by client address, and
  addresses move. Each device keeps one row per stretch at an address, ended only when another
  device is seen there, so "which device was 192.0.2.50 at 14:00" has an answer and a range
  extender answering for two addresses doesn't add a row per scan.
- **One package, one systemd unit per component.** Each service gets only what it needs: the
  loggers read the journal (`systemd-journal` group) with no network; the updater has the network
  but nothing else; the scanner sends ARP frames and nothing else. `systemd-analyze security`
  rates them 0.6, 0.6, 1.1 and 1.4; CI fails above 2.0.
- **Atomic, commit-pinned deploys.** Every install builds a virtualenv for one commit and only
  then switches the `current` symlink with `rename(2)`; installing an older ref is the rollback.
- **SQLite in WAL mode.** One host and a low write rate don't justify a database server. WAL lets
  the CLI read while the logger writes; writes take the lock up front (`BEGIN IMMEDIATE`).
- **Metrics through node_exporter, not a new listener.** `netwatch metrics` reads the database
  read-only and writes a file for node_exporter's textfile collector, so the host that answers the
  LAN's DNS opens no extra port of its own and the writer has no network at all. The counts are
  rows stored plus rows deleted by retention, kept in the same transaction as the delete, so a
  counter never drops (Prometheus reads a drop as a restart). Domain names, addresses and MAC
  addresses are never labels: each distinct value is a separate series, and those are unbounded.
  A per-minute heartbeat from each journal follower tells a stuck ingester from a quiet network.

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
- **Device discovery sees IPv4 devices on one subnet only**, at most a /22. Devices on another
  VLAN, behind another router, or on a guest Wi-Fi with client isolation are invisible, and an
  IPv6-only device isn't seen.
- **A device that's asleep may not answer.** A locked phone in Wi-Fi power save can miss both
  passes, so it can be missing from the baseline (the owner's phone was, on the VM) and then
  alert when it wakes, or look absent for a while. A device that joins and leaves between two scans, five minutes apart,
  is never seen.
- **Private Wi-Fi addresses that change look like new devices.** iOS and Android can change a
  phone's address per network or over time; each new one is a new device and one alert. On the
  VM, turning the phone's private address off and back on gave it a different one.
- **A Wi-Fi range extender may answer for its clients** with its own MAC address, so devices
  behind it share one entry.
- **Only "new MAC address" is detected.** Two devices answering for one address (an address
  conflict, or ARP spoofing) are both recorded, but nothing alerts on it.
- **Alerts aren't sent anywhere yet**; the health alerts fire in Prometheus and show in Grafana,
  and Netwatch's own alerts are in `netwatch alerts`, but nothing is pushed to a phone until
  Telegram in Phase 5.
- **The monitoring host is a second machine to keep running.** If it is down, nothing is recorded
  while it is off and no alert can fire; Netwatch keeps working regardless, since it only writes a
  file. Prometheus keeps 30 days or 5 GB, whichever comes first.
- **Metrics are scraped every 30 seconds and the file is rewritten every minute**, so a burst
  shorter than that is smoothed; per-query and per-device detail stays in the CLI, never in a
  metric label.
- **Privacy.** The database records which device looked up which name for 30 days, SSH logins
  and device address history for 90, and the device inventory until it is deleted. It is readable
  only by root and the `netwatch` user.
- **IPv4 listen address only** is configured; clients reaching the host over IPv6 aren't served.
- **One host.** Linux with systemd only; the Python code runs on Windows for development and
  tests, the services don't. `install.sh` needs access to GitHub and PyPI.

## Development

```
pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
shellcheck deploy/*.sh deploy/bin/netwatch monitoring/setup.sh
```

If dnsmasq is installed, the tests also start the real resolver with the generated configuration.
CI runs ruff, pytest on Python 3.12 to 3.14 on Linux (with dnsmasq) and 3.14 on Windows, a
monitoring job (promtool checks the Prometheus config, the alert rules and their unit tests, and
the metrics output), and a deploy job on a real systemd host: install with DNS, discovery and
metrics; query through dnsmasq and check the queries are stored (including across a restart of the
logger); fail six SSH logins against the runner's sshd and check each is stored once with one
alert; scan a test LAN (a bridge with devices in network namespaces) and check the baseline and
exactly one alert for a device that joins later; check node_exporter serves Netwatch's metrics on
the listen address only; bring up the monitoring stack and confirm Prometheus scrapes the host and
Grafana serves the dashboards; then install a release without discovery and go forward again,
reinstall, and uninstall `--purge`.

AI-assisted implementation; architecture, operations and verification are human-owned.

## License

MIT. See [LICENSE](LICENSE).
