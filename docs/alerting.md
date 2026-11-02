# Alerting: Telegram

Netwatch sends its alerts to a private Telegram chat with a bot of your own. Two senders use the
same bot and the same chat:

```
 Netwatch host                                       monitoring host (Docker)
 -----------------------------------------------     -------------------------------------
 netwatch-auth, netwatch-discovery                   Prometheus: 12 health alert rules
   -> alerts table (SQLite)                            -> Alertmanager 127.0.0.1:9093
 netwatch-notify (polls every 10 s)                       groups, repeats, "resolved"
   -> HTTPS -> api.telegram.org <------- HTTPS -----------+
                     |
                     v
          your private chat with the bot
```

- **Security alerts** (failed-login attacks, new devices, restarts of the host) are Netwatch's own
  alerts. `netwatch-notify` on the Netwatch host sends them from the shared alerts table.
- **Health alerts** (a service down, stale data, a filling disk, alerts not being delivered) are
  Prometheus rules on the monitoring host. Alertmanager sends them
  ([monitoring.md](monitoring.md)).

Neither side opens a port for this: both make outgoing HTTPS requests to Telegram only.

## What arrives on the phone

| From | Alert | Severity | Sound |
|---|---|---|---|
| netwatch-notify | `ssh-login-after-failures`: a successful login from an address under brute-force alert | critical | yes |
| netwatch-notify | `ssh-brute-force`: 5 failed logins from one address in 10 minutes | warning | silent |
| netwatch-notify | `new-device`: a MAC address seen for the first time after the baseline | warning | silent |
| netwatch-notify | `restart`: the host was down and came back (see below) | warning | silent |
| netwatch-notify | `test`: `netwatch notify test`, and every `install.sh` run | - | yes |
| Alertmanager | critical health alerts (NetwatchDown, a service down or stalled, alerts not sent, disk almost full) | critical | yes, repeated every 4 h while firing |
| Alertmanager | warning health alerts (stale metrics, scans or blocklist, a failed unit, a crash loop, a filling disk) | warning | silent, repeated daily |

Alertmanager also sends a "RESOLVED" message when a health alert stops firing. Netwatch's own
alerts are events, so they have no "resolved".

A security alert looks like this (documentation addresses):

```
🔴 CRITICAL: ssh-login-after-failures
successful SSH login as 'alice' from 192.0.2.10 after a brute-force alert for it within 10 minutes
netwatch, 10:59:55 GMT
```

## Setting it up

You need Telegram on your phone. The bot is free and belongs to your Telegram account.

1. **Create the bot.** In Telegram, open **@BotFather**, send `/newbot`, and pick a display name
   and a username ending in `bot`. BotFather replies with the bot's token, a line like
   `123456789:AAE...`. Treat it like a password: anyone with it can send messages as the bot and
   read what is sent to it.
2. **Say hello to the bot.** Open the chat with your new bot and send `/start`. A bot can't start
   a conversation itself, so until you do, Telegram refuses its messages to you.
3. **Give the Netwatch host the token.** It goes in a file only root can read, not in
   `netwatch.env`. Run this, paste the token, press Enter, then Ctrl+D (the token stays out of
   the shell history and the process list; `install.sh` sets the owner and mode again anyway):

   ```
   sudo sh -c 'umask 077; cat > /etc/netwatch/telegram-bot-token'
   ```

4. **Find your chat ID.** Run `install.sh` with the release you already have (or v0.6.0). With a
   token and no chat ID, it lists the chats that have written to the bot:

   ```
   install: Telegram: a bot token is in /etc/netwatch/telegram-bot-token, but NETWATCH_TELEGRAM_CHAT_ID is not set.
   install: Chats that have messaged the bot (send it /start first if this is empty):
   CHAT ID    TYPE     NAME
   123456789  private  Alice @alice
   ```

   `sudo /opt/netwatch/current/venv/bin/netwatch notify chats` shows the same list. It has to
   run as root because only root can read the token; it writes nothing.

5. **Turn notifications on.** Set the ID in `/etc/netwatch/netwatch.env` and run `install.sh`
   again:

   ```
   NETWATCH_TELEGRAM_CHAT_ID=123456789
   ```

   `install.sh` starts `netwatch-notify` and sends a test message through it ("Installed netwatch
   0.6.0 ... from v0.6.0"). It stops with an error if the message doesn't go out within 30
   seconds. From now on, every install sends one, so the chat also keeps a record of what was
   installed when.

6. **Give the monitoring host the same token and chat.** On the monitoring host:

   ```
   sudo sh -c 'umask 077; d=/opt/netwatch-monitoring/monitoring/secrets/telegram; mkdir -p $d && cat > $d/bot_token'
   sudoedit /opt/netwatch-monitoring/monitoring/.env          # TELEGRAM_CHAT_ID=123456789
   sudo /opt/netwatch-monitoring/monitoring/setup.sh
   sudo /opt/netwatch-monitoring/monitoring/setup.sh --test-alert
   ```

   The first command reads the token like step 3. `setup.sh` gives the token file to Alertmanager's
   user (read-only), writes the chat ID next to it and switches Alertmanager from `off.yml` to
   `telegram.yml`. `--test-alert` adds a critical test alert to the running Alertmanager. It arrives
   within about 30 seconds, and a "RESOLVED" message follows a few minutes after it expires (two
   minutes). The test alert exists only in Alertmanager's memory, so running `setup.sh` again before
   it has resolved drops it and no "resolved" follows; Prometheus's own alerts are sent again by
   Prometheus and aren't affected.

## How netwatch-notify decides what to send

It checks the alerts table every 10 seconds for alerts it hasn't dealt with, oldest first.

- **Baseline.** Its first start records the time. Alerts raised before that are never sent, so
  switching notifications on for a host with history doesn't replay weeks of old alerts.
- **Cooldown.** A repeat of an alert (same kind, same subject: an address or a MAC) within 30
  minutes of the last message about it is held back ("suppressed"), and the first repeat after
  that is sent. The detectors already raise one alert per incident, so this rarely triggers. It
  is a second line of defence against a detector bug turning into a flood. Tests and restarts
  are always sent. `NETWATCH_NOTIFY_COOLDOWN_MINUTES` changes the 30.
- **Bursts.** At most 10 messages a minute (Telegram allows about one a second per chat). When
  more alerts wait than that allows, they go out as one summary instead ("3 alerts at once: 2
  new-device, 1 ssh-login-after-failures ... list them on the host with: netwatch alerts").
- **At least once.** An alert is marked as sent (`notified_us`) only after Telegram has accepted
  the message. If Telegram or the internet can't be reached, the alert waits and goes out when
  they are back, with the time it was raised. A crash between Telegram's answer and the commit
  would send that one message twice, never zero times.
- **Retries.** After a temporary failure (no connection, a timeout, a server error), it waits 10
  seconds, doubling up to 5 minutes. When Telegram says "too many requests", it waits as long as
  Telegram asks. A wrong token or chat ID is retried every 5 minutes, with an error in the
  journal saying what to check.

`notified_us` therefore means "dealt with": sent on its own, summarised or suppressed. The counts
of each are in `netwatch notify status` and in the metrics.

```
netwatch notify status       # on or off, since when, sent / suppressed / summarised, waiting, errors
netwatch notify test [--message TEXT]   # a message through the running service
sudo /opt/netwatch/current/venv/bin/netwatch notify chats   # chats that wrote to the bot
journalctl -u netwatch-notify
```

`netwatch notify test` doesn't send anything itself. It queues a test alert and waits until the
service has sent it, so it tests what real alerts depend on: the running service, its token, its
sandbox and its network access.

## Restarts of the host

Both Netwatch VMs run on one desktop PC. When that PC crashes, nothing can send an alert until it
is back. So `netwatch-notify` records a heartbeat every minute, and when it starts it compares its
last heartbeat with the time the host booted. A heartbeat from before the boot means the host
was down in between, and it raises a `restart` alert:

```
🟡 WARNING: restart
The host restarted: last heartbeat 10:13:00 GMT, booted 10:50:00 GMT, down for about 37 min. Nothing on it could alert in between.
netwatch, 10:50:41 GMT
```

You learn about an outage afterwards, not while it lasts. A restart of the service alone (an
install, a crash of netwatch-notify) isn't a restart of the host, so it raises nothing.

## Who watches the notifier

The two paths cover for each other where they can:

- **netwatch-notify is down or stuck:** its heartbeat goes stale and Prometheus fires
  NetwatchServiceStalled (critical) through Alertmanager. A crash loop fires
  NetwatchServiceRestarting.
- **netwatch-notify runs but nothing gets through** (wrong chat ID, Telegram refusing it):
  `netwatch_alerts_oldest_unsent_timestamp_seconds` keeps its old value, and after 10 minutes
  NetwatchAlertsNotSent (critical) goes out through Alertmanager.
- **Alertmanager can't deliver:** nothing on the phone. Its own page (SSH tunnel to port 9093)
  and Grafana still show the alerts.

What nothing here covers: the PC being down (both VMs are on it), Telegram itself being down, or
a revoked token, which breaks both senders at once since they share it.

## Security and privacy

- **The token.** On the Netwatch host it is in `/etc/netwatch/telegram-bot-token`, owned by root,
  mode 0600. `netwatch-notify` gets it through systemd's `LoadCredential=`: systemd copies it into
  a directory only that service can see, so it is not in `netwatch.env` (which every Netwatch
  service reads) and not an environment variable (which child processes inherit). It is never
  logged; error messages carry Telegram's description instead, and CI checks the journal for it.
  On the monitoring host it is a file readable by Alertmanager's user only, mounted read-only.
- **What leaves the LAN.** Messages contain LAN addresses, MAC addresses, usernames from SSH logs
  and the host's name. They go through Telegram's servers; chats with a bot are ordinary cloud
  chats, not end-to-end encrypted.
- **If the token leaks:** in @BotFather, `/revoke` the token, then put the new one in both files
  and run `install.sh` and `setup.sh` again.
- **The notifier's sandbox:** no capabilities, no write access outside `/var/lib/netwatch` (and a
  private `/tmp`), and only IPv4, IPv6 and Unix sockets. It is not limited to Telegram's
  addresses, because those can change.

## Turning it off

- **Netwatch host:** empty `NETWATCH_TELEGRAM_CHAT_ID` in `netwatch.env` and run `install.sh`; it
  stops and disables `netwatch-notify`. The token file stays until you delete it (or
  `uninstall.sh --purge`).
- **Monitoring host:** empty `TELEGRAM_CHAT_ID` in `.env` and run `setup.sh`; Alertmanager keeps
  running with nowhere to send (`off.yml`).

If notifications are turned on again later, the baseline from the first start still applies:
alerts raised while they were off are sent then.

## Tested

2026-11-02, the v0.6.0 release candidate on both VMs with a real bot and a phone:

- **Baseline.** netwatch-notify's first start logged "the 9 alerts raised before now will not be
  sent": the failed-login and new-device alerts from the Phase 2 and 3 demos. None arrived.
- **Install message.** `install.sh` sent its test message through the service; Telegram accepted
  it 3 seconds after it was queued.
- **Failed-login demo.** Six failed SSH logins from the admin PC (unknown users, no keys): the
  ssh-brute-force warning arrived silently. The next key login from the same PC raised
  ssh-login-after-failures, which arrived with sound.
- **Restart.** A reboot of the Netwatch VM: after boot the notifier found its last heartbeat
  (20:16:06) older than the boot (20:16:19) and the restart alert arrived.
- **Health alerts.** `setup.sh --test-alert` arrived through Alertmanager, and its "resolved"
  message followed at the next group flush. Alertmanager counted the Telegram notifications and
  no failures.
- **Afterwards:** `netwatch notify status` showed every alert sent, none suppressed or
  summarised, none waiting and no send errors.

The run found five problems, each fixed with a test before the release:

- Writing the token with `install /dev/stdin` fails on Ubuntu 26.04 when the file already exists
  (its uutils coreutils), so the recipes above use `sh -c 'umask 077; cat > ...'`.
- A reboot shorter than a minute read "down for about under a minute".
- `setup.sh`: amtool's new label parser warned about the test alert's unquoted annotations, and
  `docker compose exec` and `run` swallowed the rest of a script piped into bash, so the commands
  after `setup.sh` silently never ran.
- A second `--test-alert` within 4 hours sent no firing message: Alertmanager doesn't repeat an
  identical alert, so each test now carries a run label.
- The test alert said "Since" its end time (amtool sends no start unless asked), and Telegram
  turned "setup.sh" in its text into a web link (.sh is a top-level domain).

