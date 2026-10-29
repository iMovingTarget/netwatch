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

## sshd-journal.jsonl

Real OpenSSH 10.2 logging from the Netwatch VM (Ubuntu 26.04.1), exported with
`journalctl -t sshd -t sshd-session -o json` on 2026-10-28. It shows eight failed logins in about
four seconds, as an unknown user each time from a client that offered no credentials (each logs
`Invalid user` and then `Connection closed by invalid user ... [preauth]`), between normal key
logins from an admin workstation.

Anonymised before committing: the attacking address (127.0.0.1 in the capture) is 203.0.113.5,
the workstation is 192.0.2.10, the account name is `alice`, and the key fingerprint and the
boot, machine and sequence IDs inside the cursors are made up. Only the fields Netwatch reads
are kept (`MESSAGE`, `__CURSOR`, `__REALTIME_TIMESTAMP`, `SYSLOG_IDENTIFIER`, `_PID`,
`PRIORITY`); the timestamps and message text are otherwise as logged. `examples/` has a copy.

## ieee-data/

Files in the format of the IEEE MAC address registry as the `ieee-data` package installs it in
`/usr/share/ieee-data/` (UTF-8, CRLF line endings; `.gitattributes` keeps them byte for byte):
`oui.txt` (24-bit MA-L blocks), `mam.txt` (28-bit MA-M) and `oui36.txt` (36-bit MA-S). The IANA
and IEEE Registration Authority entries are real; the other organisations, the addresses and two
deliberately malformed entries are made up to test longest-prefix matching and the parser.
