# How Netwatch works

The module map, every design decision with its trade-offs, every known limitation, and what the
tests and CI check. The [README](../README.md) has the short version; set-up guides are in
[monitoring.md](monitoring.md), [alerting.md](alerting.md) and [rollback.md](rollback.md).

## Overview

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
                                                                                  |
 netwatch-notify (every 10 s): alerts not yet sent -> Telegram Bot API     Alertmanager -> Telegram
     (cooldown, burst summary, restart alerts; token via LoadCredential)   (health alerts)
```

## Modules

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
| `netwatch/notify.py` | The `netwatch-notify` service: baseline, cooldown, burst summaries, retries, restart alerts, `notify test` |
| `netwatch/telegram.py` | Minimal Telegram Bot API client over HTTPS (standard library); keeps the token out of errors |
| `netwatch/storage.py` | SQLite in WAL mode, write transactions, schema versioning |
| `netwatch/logsetup.py` | Logging to stderr, with journald priorities when stderr is the journal |
| `deploy/` | Install, uninstall and host-check scripts, systemd units, example config |
| `monitoring/` | Prometheus, Alertmanager and Grafana for a separate host: Compose, scrape config, alert rules and tests, Alertmanager routes and message template, provisioned dashboards, `setup.sh` |

## Design decisions

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
  loggers read the journal (`systemd-journal` group) with no network; the updater and the notifier
  have the network but nothing else; the scanner sends ARP frames and nothing else; the metrics
  writer has neither. `systemd-analyze security` rates them 0.6 (dns, auth), 1.1 (blocklist,
  notify), 1.4 (discovery) and 0.4 (metrics); CI fails above 2.0.
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
- **Two senders, one bot.** Netwatch's own alerts are events in its database; health alerts are
  Prometheus rules that fire and resolve. Each goes through the tool built for it: netwatch-notify
  reads the alerts table, Alertmanager adds grouping, repeats and "resolved" messages. Sending
  everything through one of them would mean either turning security events into metrics (with
  addresses as labels, which is unbounded) or opening a way from the Netwatch host into
  Prometheus. The two paths watch each other where they can: a stalled notifier or an alert
  stuck for ten minutes fires a health alert through Alertmanager.
- **At least once, through the database.** An alert is marked as sent only after Telegram
  accepted it, in its own transaction, so an outage delays alerts instead of losing them; the
  price is that a crash at exactly the wrong moment sends one message twice. `netwatch notify
  test` queues a test alert and waits for the service to send it, so the test covers the real
  path (service, token, sandbox, network) rather than a second one.
- **A baseline, a cooldown and a burst limit.** Switching notifications on doesn't replay old
  alerts, a repeat of one alert within 30 minutes is held back, and more than ten waiting alerts
  become one summary. The detectors already raise one alert per incident; these stop a detector
  bug, or a backlog after an outage, from turning into a flood on the phone.
- **The token is a credential, not a setting.** It lives in a root-only file that systemd hands
  to netwatch-notify alone (`LoadCredential=`), not in `netwatch.env`, which every Netwatch
  service can read, and not in an environment variable, which child processes inherit. The
  client never puts it in an error message, and CI checks the journal for it.
- **A restart notice instead of an outside watchdog.** Both VMs run on one desktop PC, so when
  it is down nothing can alert. A dead man's switch (an outside service that alerts when pings
  stop) would report an outage while it lasts, but means an account with another service; the
  `restart` alert reports it afterwards, with when it started and ended.

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
- **Nothing can alert while the PC is down.** Both VMs run on one desktop PC; the `restart`
  alert arrives once it is back, not during the outage.
- **Telegram is a dependency.** While Telegram or the internet can't be reached, alerts wait
  (and arrive late, with the time they were raised). Both senders share one bot token, so a
  revoked token silences both, and only Alertmanager's own page and Grafana still show health
  alerts then. Messages contain LAN addresses, MAC addresses and SSH usernames and pass through
  Telegram's servers; bot chats are not end-to-end encrypted.
- **Delivery is at least once and polled every 10 seconds.** A crash between Telegram's answer
  and the database commit sends one message twice; an alert takes up to about ten seconds to
  leave the host.
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

## Testing

If dnsmasq is installed, the tests also start the real resolver with the generated configuration.
CI runs ruff, pytest on Python 3.12 to 3.14 on Linux (with dnsmasq) and 3.14 on Windows, a
monitoring job (promtool checks the Prometheus config, the alert rules and their unit tests, and
the metrics output; amtool checks both Alertmanager configurations and renders the message
template), and a deploy job on a real systemd host: install with DNS, discovery, metrics and
Telegram (against a fake Telegram API on loopback); query through dnsmasq and check the queries
are stored (including across a restart of the logger); fail six SSH logins against the runner's
sshd and check each is stored once with one alert; scan a test LAN (a bridge with devices in
network namespaces) and check the baseline and exactly one alert for a device that joins later;
check each alert reached the fake Telegram exactly once, warnings silently, and that the bot
token is in no log line; check node_exporter serves Netwatch's metrics on the listen address
only; bring up the monitoring stack and confirm Prometheus scrapes the host and finds
Alertmanager, and Grafana serves the dashboards; then install a release without discovery and go
forward again, reinstall, and uninstall `--purge`.
