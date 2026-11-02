# Using Netwatch

The [README](../README.md) has the short version. This page has the long one: what each part
records and alerts on, how to try Netwatch without a host, and how to deploy and run it, with
real output (addresses replaced with documentation ones).

## What each part does

### DNS

- **Forwarding:** names that aren't blocked go to the upstream servers (default 1.1.1.1 and
  9.9.9.9), with dnsmasq's cache in front.
- **Blocking:** names on the blocklist get `0.0.0.0` (A) and `::` (AAAA). The default list is
  [StevenBlack's unified hosts](https://github.com/StevenBlack/hosts) (about 76,000 domains);
  any https hosts-format or one-domain-per-line list works, and an allowlist overrides them.
- **Logging:** every query is stored for 30 days as forwarded, cached, blocked, local (answered by
  dnsmasq's own rules) or no-answer.

### SSH logins

- **Every login is stored** for 90 days: time, client address, account, failed or accepted, the
  method, and whether the account exists.
- **ssh-brute-force** (warning): 5 failed logins from one address within 10 minutes (both
  configurable). One alert per address per window, however long the attack goes on.
- **ssh-login-after-failures** (critical): a successful login from an address with a
  brute-force alert in the last window. One per brute-force alert.
- Alerts go to a table every detector shares (`netwatch alerts`, and the journal at warning
  priority); `netwatch-notify` sends them to Telegram.

### LAN devices

Opt-in: set `NETWATCH_DISCOVERY_INTERFACE`, for example `eth0`.

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

On the VM: discovery was switched on with the router and the admin PC online. The owner's
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

### Metrics and dashboards

Opt-in: set `NETWATCH_METRICS_LISTEN`.

- **`netwatch metrics`** writes the DNS, login, alert and device numbers, each component's
  heartbeat, the blocklist and database sizes and the running version in the Prometheus text
  format. A timer writes it every minute; node_exporter serves it alongside the host's own
  metrics and the systemd state of Netwatch's units. Netwatch never listens on the network for
  this. The counters survive retention, and no domain, address or MAC becomes a metric label.
- **A separate monitoring host** runs Prometheus, Alertmanager and Grafana in Docker, with twelve
  health alerts (host or a service down, a stalled service, stale metrics, scans or blocklist, a
  filling disk, alerts not reaching Telegram) and two dashboards. It is built from a tag like the
  Netwatch host is. See [monitoring.md](monitoring.md).

### Notifications

Opt-in: a bot token in its own root-only file and `NETWATCH_TELEGRAM_CHAT_ID`;
set up in [alerting.md](alerting.md).

- **`netwatch-notify`** sends every new alert to a private Telegram chat within about ten
  seconds: critical ones (`ssh-login-after-failures`) with sound, warnings silently.
- **No floods, no replays.** Alerts from before notifications were switched on are never sent;
  a repeat of the same alert within 30 minutes is held back; more than ten at once arrive as one
  summary. An alert counts as sent only once Telegram accepted it, so alerts raised while the
  internet is down go out when it is back.
- **restart** (warning): on start, a heartbeat older than the host's boot means the host was
  down; the message says from when to when.
- **Health alerts** go through Alertmanager on the monitoring host, with the same bot: grouped,
  repeated while they fire, and with a "resolved" message.
- `netwatch notify test` sends a message through the running service, and every `install.sh`
  run sends one saying what was installed.

## Trying it without a host

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
sudo deploy/install.sh v0.6.0                # first install: creates /etc/netwatch/netwatch.env
sudoedit /etc/netwatch/netwatch.env          # set NETWATCH_DNS_LISTEN, NETWATCH_DNS_ALLOW_FROM,
                                             # NETWATCH_DISCOVERY_INTERFACE, for Phase 4
                                             # NETWATCH_METRICS_LISTEN / NETWATCH_METRICS_ALLOW_FROM
                                             # and, for Phase 5, NETWATCH_TELEGRAM_CHAT_ID
sudo deploy/install.sh v0.6.0                # again, now with DNS, discovery, metrics, Telegram
```

Telegram needs a bot token in `/etc/netwatch/telegram-bot-token` first; `install.sh` helps find
the chat ID. The steps are in [alerting.md](alerting.md).

The upgrade on the VM to the v0.6.0 release candidate, with DNS, discovery, metrics and Telegram
configured (LAN addresses and the chat ID replaced with documentation ones):

```
install: keeping the existing /etc/netwatch/netwatch.env
install: setting up dnsmasq on 192.0.2.53
install: ufw: allowed DNS from 192.0.2.0/24 to 192.0.2.53
install: setting up node_exporter on 192.0.2.53:9100
install: ufw: allowed metrics scrapes from 192.0.2.201 to 192.0.2.53:9100
192.0.2.53: example.com A -> NOERROR 172.66.147.243, 104.20.23.154 (161 ms)
192.0.2.53: 0.0.0.0.creative.hpyrdr.com A -> NOERROR 0.0.0.0 (blocked)
install: scanning the LAN on eth0
install: last scan 2026-11-02 20:19:27: 3 of 4 devices answered
install: node_exporter serves 30 netwatch samples on 192.0.2.53:9100
install: sending a test message to Telegram chat 123456789
test alert 14 sent to Telegram chat 123456789 in 3 s
install: installed netwatch 0.6.0 (revision a4b0d5475c70) from phase-5-telegram
install:   netwatch-auth.service: active
install:   netwatch-dns.service: active
install:   netwatch-notify.service: active
install:   netwatch-blocklist.timer: active
install:   netwatch-discovery.timer: active
install:   netwatch-metrics.timer: active
```

Then point one device's DNS at the host's LAN address and watch it with `netwatch dns recent`.
[rollback.md](rollback.md) describes how to switch a device back, stop DNS, roll back
to an older version or remove Netwatch. Installing an older ref is the version rollback;
`sudo deploy/uninstall.sh [--purge]` removes everything.

| Path | Contents |
|---|---|
| `/opt/netwatch/releases/<commit>/` | One virtualenv per installed commit, owned by root |
| `/opt/netwatch/current` | Symlink to the active release |
| `/etc/netwatch/netwatch.env` | Settings, no secrets. `root:netwatch`, mode 0640 |
| `/etc/netwatch/telegram-bot-token` | The Telegram bot token. `root:root`, mode 0600; netwatch-notify gets it through `LoadCredential=` |
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
netwatch notify status                 # what was sent, held back, summarised; what still waits
netwatch notify test [--message TEXT]  # a message through the running netwatch-notify
sudo systemctl start netwatch-discovery.service   # scan now instead of within five minutes
journalctl -u 'netwatch*' -u dnsmasq
```
