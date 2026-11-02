#!/usr/bin/env bash
# Set up or update Netwatch's monitoring stack (Prometheus, Alertmanager and Grafana) on this host.
#
#   git clone --branch <tag> https://github.com/iMovingTarget/netwatch.git /opt/netwatch-monitoring
#   sudo /opt/netwatch-monitoring/monitoring/setup.sh
#   sudo /opt/netwatch-monitoring/monitoring/setup.sh --test-alert   # a test alert to Telegram
#
# Run it again after editing .env or checking out a newer tag. It:
# 1. installs Docker and Compose from Ubuntu's archive if they are missing, so unattended-upgrades
#    keeps them patched;
# 2. on the first run, creates .env from .env.example and a random Grafana admin password in
#    secrets/ (neither is committed, and neither is ever overwritten);
# 3. writes Prometheus's scrape target from NETWATCH_TARGET in .env, and Alertmanager's
#    configuration: Telegram when TELEGRAM_CHAT_ID is set (the bot token must be in
#    secrets/telegram/bot_token), nowhere otherwise;
# 4. checks the Prometheus and Alertmanager configurations and runs the alert rules' unit tests,
#    and stops if any of them fails, before anything is restarted;
# 5. (re)creates the containers and waits until Prometheus, Alertmanager and Grafana answer.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
PROMETHEUS_URL=http://127.0.0.1:9090
ALERTMANAGER_URL=http://127.0.0.1:9093
GRAFANA_UID=472      # the user Grafana's image runs as
ALERTMANAGER_UID=65534 # nobody, the user Alertmanager's image runs as

log() { printf 'setup: %s\n' "$*"; }
die() {
    printf 'setup: error: %s\n' "$*" >&2
    exit 1
}

# The value of a setting in .env (last one wins), without quotes.
setting() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$here/.env" |
        tail -n 1 | sed -e "s/^[\"']//" -e "s/[\"'][[:space:]]*$//" -e 's/[[:space:]]*$//'
}

# Wait up to $2 seconds for URL $1 to answer with a 2xx status.
wait_for() {
    local deadline=$((SECONDS + $2))
    until curl -fs -o /dev/null "$1"; do
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 2
    done
}

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
cd "$here"

# --test-alert: one alert through Alertmanager to Telegram, on the running stack. It resolves by
# itself two minutes later, so a "resolved" message follows within about five more. Annotation
# values are double-quoted inside the argument, as amtool's label parser expects; stdin is closed
# so `docker compose exec` can't swallow the rest of a script that pipes commands into bash.
if [ "${1:-}" = --test-alert ]; then
    docker compose exec -T alertmanager amtool --alertmanager.url=http://127.0.0.1:9093 \
        alert add NetwatchTestAlert severity=critical \
        --annotation='summary="Test alert from setup.sh --test-alert"' \
        --annotation='description="Health alerts reach Telegram through Alertmanager."' \
        --end="$(date -u -d '+2 min' +%Y-%m-%dT%H:%M:%SZ)" </dev/null ||
        die "could not add the test alert (is the stack running? docker compose ps)"
    log "test alert added: Telegram should show it within a minute, and RESOLVED a few after"
    exit 0
fi
[ $# -eq 0 ] || die "usage: setup.sh [--test-alert]"

# 1. Docker and Compose.
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    log "installing Docker and Compose from Ubuntu's archive"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null
    apt-get install -y -q docker.io docker-compose-v2 >/dev/null ||
        die "could not install docker.io and docker-compose-v2"
fi
command -v curl >/dev/null || die "curl not found"
systemctl enable --now --quiet docker.service

# 2. Settings and the admin password, created once.
if [ ! -e .env ]; then
    install -m 0600 .env.example .env
    die "created $here/.env from the example: set GRAFANA_LISTEN and NETWATCH_TARGET, then run this again"
fi
chmod 0600 .env
grafana_listen=$(setting GRAFANA_LISTEN)
target=$(setting NETWATCH_TARGET)
[[ $grafana_listen =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] ||
    die "GRAFANA_LISTEN in .env must be this host's LAN IPv4 address, not '$grafana_listen'"
[[ $target =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+$ ]] ||
    die "NETWATCH_TARGET in .env must be address:port, e.g. 192.0.2.200:9100, not '$target'"
case $grafana_listen in
192.0.2.* | 198.51.100.* | 203.0.113.*)
    die "GRAFANA_LISTEN is still the documentation example ($grafana_listen): set this host's address in .env"
    ;;
esac

install -d -m 0700 secrets
if [ ! -s secrets/grafana_admin_password ]; then
    head -c 18 /dev/urandom | base64 | tr -d '/+=\n' >secrets/grafana_admin_password
    log "created a Grafana admin password in $here/secrets/grafana_admin_password"
fi
# Mounted into the container as a file: readable by Grafana's user only.
chown "$GRAFANA_UID:0" secrets/grafana_admin_password
chmod 0400 secrets/grafana_admin_password

# Alertmanager reads the bot token and the chat ID from secrets/telegram/ as its own user.
install -d -m 0700 secrets/telegram
chown "$ALERTMANAGER_UID:0" secrets/telegram
chat_id=$(setting TELEGRAM_CHAT_ID)
if [ -n "$chat_id" ]; then
    [[ $chat_id =~ ^-?[0-9]+$ ]] ||
        die "TELEGRAM_CHAT_ID in .env must be a Telegram chat ID such as 123456789, not '$chat_id'"
    [ -s secrets/telegram/bot_token ] ||
        die "TELEGRAM_CHAT_ID is set, but there is no bot token in $here/secrets/telegram/bot_token"
    printf '%s' "$chat_id" >secrets/telegram/chat_id
    for file in secrets/telegram/bot_token secrets/telegram/chat_id; do
        chown "$ALERTMANAGER_UID:0" "$file"
        chmod 0400 "$file"
    done
    install -m 0644 alertmanager/telegram.yml alertmanager/alertmanager.yml
    log "Alertmanager sends health alerts to Telegram chat $chat_id"
else
    rm -f secrets/telegram/chat_id
    install -m 0644 alertmanager/off.yml alertmanager/alertmanager.yml
    log "TELEGRAM_CHAT_ID is not set in .env: health alerts are not sent anywhere"
fi

# 3. The scrape target. The instance label is a name, so no address shows up in Grafana.
cat >prometheus/targets/netwatch.yml <<EOF
# Written by setup.sh from NETWATCH_TARGET in .env; edit .env instead.
- targets: ["$target"]
  labels:
    instance: netwatch
EOF
chmod 0644 prometheus/targets/netwatch.yml

# 4. Check before restarting anything.
docker compose config --quiet || die "compose.yaml or .env is invalid (see above)"
promtool() {
    docker compose run --rm --no-deps --quiet-pull --entrypoint promtool prometheus "$@"
}
promtool check config /etc/prometheus/prometheus.yml >/dev/null ||
    die "the Prometheus configuration is invalid (see above)"
promtool test rules /etc/prometheus/tests/netwatch.test.yml >/dev/null ||
    die "the alert rules failed their unit tests (see above)"
docker compose run --rm --no-deps --quiet-pull --entrypoint amtool alertmanager \
    check-config /etc/alertmanager/alertmanager.yml >/dev/null ||
    die "the Alertmanager configuration is invalid (see above)"
log "configuration and alert rule tests pass"

# 5. Start, then wait for both to answer.
docker compose up --detach --force-recreate --remove-orphans --quiet-pull
wait_for "$PROMETHEUS_URL/-/ready" 60 || die "Prometheus is not ready (docker compose logs prometheus)"
wait_for "$ALERTMANAGER_URL/-/ready" 60 ||
    die "Alertmanager is not ready (docker compose logs alertmanager)"
wait_for "http://$grafana_listen:3000/api/health" 90 ||
    die "Grafana does not answer on $grafana_listen:3000 (docker compose logs grafana)"

# The target's state after its first scrape (every 30 seconds).
sleep 35
health=$(curl -fsS "$PROMETHEUS_URL/api/v1/targets?state=active" |
    python3 -c 'import json, sys
for t in json.load(sys.stdin)["data"]["activeTargets"]:
    print(t["labels"]["job"], t["health"], t["lastError"] or "")') ||
    die "cannot read the targets from Prometheus"
while read -r job state error; do
    log "target $job: $state${error:+ ($error)}"
done <<<"$health"
log "Grafana: http://$grafana_listen:3000 (user admin, password in $here/secrets/grafana_admin_password)"
log "Prometheus: ssh -L 9090:127.0.0.1:9090 <user>@$grafana_listen, then http://localhost:9090"
log "Alertmanager: ssh -L 9093:127.0.0.1:9093 <user>@$grafana_listen, then http://localhost:9093"
