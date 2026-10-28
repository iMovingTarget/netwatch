# Test fixtures

## dnsmasq-journal.jsonl

Real dnsmasq 2.91 query logging, one JSON object per line in the shape `journalctl -o json`
produces. Only `MESSAGE` is dnsmasq's output; `__CURSOR`, `__REALTIME_TIMESTAMP`, `_PID` and
`SYSLOG_IDENTIFIER` were added by the capture script (the timestamps are the real capture times,
the cursors are placeholders).

How it was captured, in a sandbox with documentation addresses (RFC 5737) on the loopback
interface:

- A second dnsmasq on 198.51.100.1 played the upstream resolver, with fixed records for
  `example.com`, `example.org` (A and AAAA), `www.example.net` (a CNAME), `multi.example.com`
  (two A records) and a TXT record, `local-ttl=300` so answers are cached, and NXDOMAIN for
  everything else.
- The dnsmasq under test listened on 192.0.2.53 with the settings Netwatch uses:
  `log-queries=extra`, `domain-needed`, `bogus-priv`, `server=198.51.100.1`, an extra
  `server=/dead.example/192.0.2.99` that never answers, and
  `hostsdir=/var/lib/netwatch-blocklist` holding a two-name blocklist.
- `dig` sent the queries from 192.0.2.10 and 192.0.2.11, including one over TCP (answered by a
  dnsmasq child process with its own PID). Midway the blocklist was replaced by an atomic rename
  (dnsmasq reloads it through inotify), and at the end dnsmasq was restarted once.
