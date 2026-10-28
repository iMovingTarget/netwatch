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
sudo deploy/install.sh v0.1.0      # any tag, branch or commit
```

Installing an older ref switches `/opt/netwatch/current` back atomically and installs that
version's units. v0.1.0 has no DNS service, so this also removes `netwatch-dns`; run step 4 as
well to stop dnsmasq.

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
