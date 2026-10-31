# Rollback: taking Netwatch out of the DNS path

Netwatch only answers DNS for devices that were pointed at it by hand. Every other device keeps
using the router, so a broken Netwatch can't take the whole house offline. Rolling back is about
those test devices first, and about the server second.

Do the steps in order. Step 1 alone is a complete rollback for a device.

## 1. Switch the device back to automatic DNS (seconds)

- **iPhone or iPad:** Settings > Wi-Fi > (i) next to the home network > Configure DNS >
  **Automatic**.
- **Android** (menus vary by maker): Settings > Network & internet > Internet > the gear next to
  the home network > Edit > Advanced options > IP settings > **DHCP**.
- **Windows:** Settings > Network & internet > Wi-Fi or Ethernet > DNS server assignment > Edit >
  **Automatic (DHCP)**. Or, in PowerShell as administrator:
  `Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses`

Check it worked: the device loads web pages, and on a computer `nslookup example.com` names a
server other than the Netwatch host.

## 2. Stop Netwatch answering, keeping everything installed

```
sudo systemctl stop dnsmasq        # undo: sudo systemctl start dnsmasq
```

Any device still pointed at Netwatch loses DNS at this point, which is why step 1 comes first.

## 3. Go back to an earlier Netwatch version

```
sudo deploy/install.sh v0.3.0      # any tag, branch or commit
```

Installing an older ref switches `/opt/netwatch/current` back atomically and installs that
version's units, removing the ones it doesn't ship. v0.3.0 has no device discovery, so this
removes `netwatch-discovery` and its timer (and skips the first scan); the inventory stays in
the database. v0.1.0 has no DNS service, so going back that far also removes `netwatch-dns`;
run step 4 as well to stop dnsmasq.

**Across a database upgrade.** A release refuses a database written by a newer schema, so after
going back from v0.4.0 (schema 4) to v0.3.0 (schema 3), `netwatch-dns` and `netwatch-auth` keep
restarting with "database schema version 4 is newer than this Netwatch supports (3)". dnsmasq
keeps answering; only logging and alerting stop. `install.sh` reports the failed service and
prints the command to go forward again. To stay on the older release instead, set the database
aside and let the services start an empty one:

```
d=/var/lib/netwatch
sudo systemctl stop netwatch-dns netwatch-auth
for f in netwatch.db netwatch.db-wal netwatch.db-shm; do
    if sudo test -e "$d/$f"; then sudo mv "$d/$f" "$d/$f.saved"; fi
done
sudo systemctl start netwatch-dns netwatch-auth
```

To get the history back later, replace the database the older release started with the saved
one, then install the newer release. What was logged while on the older release is dropped; a
leftover write-ahead log from it must not be applied to the saved database, so all three files
go:

```
d=/var/lib/netwatch
sudo systemctl stop 'netwatch-*'
for f in netwatch.db netwatch.db-wal netwatch.db-shm; do
    sudo rm -f "$d/$f"
    if sudo test -e "$d/$f.saved"; then sudo mv "$d/$f.saved" "$d/$f"; fi
done
sudo deploy/install.sh v0.4.0
```

The device inventory comes back with the database, so the baseline isn't recorded a second time.

**Metrics across a downgrade to before v0.5.0.** A release older than v0.5.0 has no
`netwatch-metrics` unit, so `install.sh` removes it, but node_exporter stays installed and keeps
serving the last metrics file, which no longer changes; the `NetwatchMetricsStale` alert then
fires, correctly. Remove the stale file (`sudo rm /var/lib/netwatch-metrics/netwatch.prom`) to
silence it, or run `uninstall.sh`, which stops node_exporter and removes it. See
[monitoring.md](monitoring.md).

## 4. Remove Netwatch from the host

```
sudo deploy/uninstall.sh           # keeps settings and stored queries
sudo deploy/uninstall.sh --purge   # removes everything, including the netwatch user
```

This stops and disables dnsmasq, removes Netwatch's dnsmasq configuration
(`/etc/dnsmasq.d/netwatch.conf` and the systemd drop-in), the ufw rules tagged `netwatch dns`,
the blocklist and the services. The host's own name resolution never depended on Netwatch, so
nothing else changes on it.

## Whole-house DNS (not used yet)

The router's DHCP settings still hand out the router as the DNS server. Pointing them at Netwatch
is out of scope while Netwatch runs on a desktop PC that isn't always on. If that changes, the
rollback is to restore the router's DNS setting first; devices pick it up when their DHCP lease
renews (reconnecting to Wi-Fi forces it).

## Tested

2026-10-28, Netwatch on the Hyper-V VM (Ubuntu Server 26.04.1, dnsmasq 2.92):

- An iPhone was pointed at Netwatch (Configure DNS > Manual). About 200 lookups in two minutes
  were stored, and Google and Apple ad and analytics domains were blocked.
- Step 1 was carried out: Configure DNS > Automatic. The phone's last lookup through Netwatch was
  its connectivity check (`captive.g.aaplimg.com`) at the moment of the change; none arrived
  afterwards, and the phone kept working.
- The VM had restarted earlier that afternoon; dnsmasq, `netwatch-dns` and the blocklist timer
  all came back on their own, with no failed units.
- Steps 2 to 4 are exercised on every pull request by CI's deploy job (stop and restart of the
  logger, reinstall, uninstall `--purge` on a real systemd host).
- Later that day, step 3 across a database upgrade: from the Phase 2 release candidate back to
  v0.2.0. `netwatch-dns` failed as described and dnsmasq kept answering; with the database set
  aside v0.2.0 ran on an empty one; going forward again and moving the database back restored
  every stored query, login and alert, with no failed units.

2026-10-29, the Phase 3 release candidate (schema 4) on the same VM:

- Step 3 across the upgrade to schema 4: `install.sh v0.3.0` removed `netwatch-discovery` and its
  timer, skipped the scan, and stopped with "netwatch-auth.service did not start" and the command
  to go forward; both loggers logged the schema error while dnsmasq kept answering.
- With the database set aside, v0.3.0 ran on an empty one with no failed units.
- Going forward with the commands above restored the database (DNS queries, logins, alerts,
  devices and address history); the logger caught up on the queries made in between from the
  journal, and the next scan reported "2 devices, 0 new", so the baseline wasn't recorded again.
