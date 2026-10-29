#!/usr/bin/env bash
# Install or upgrade Netwatch on this host from a git ref: a tag, a branch or a commit.
#
#   sudo ./install.sh v0.1.0
#   sudo ./install.sh phase-0-foundation
#
# Each install builds a virtualenv for the exact commit under /opt/netwatch/releases/<commit>,
# smoke-tests it, and only then points /opt/netwatch/current at it with an atomic rename. A failed
# download or build leaves the running version untouched. Installing an older ref is the rollback.
#
#   /opt/netwatch/releases/<commit>/   code, owned by root and read-only to the service
#   /opt/netwatch/current              symlink to the active release
#   /etc/netwatch/netwatch.env         settings and secrets (root:netwatch 0640), never overwritten
#   /var/lib/netwatch/                 state, created by systemd (StateDirectory=)
#   /etc/systemd/system/netwatch-*     units shipped in deploy/systemd/ of the installed commit
#   /usr/local/bin/netwatch            CLI wrapper that runs as the netwatch user
#
# When NETWATCH_DNS_LISTEN is set in netwatch.env, it also sets up DNS: it installs dnsmasq if
# needed, writes /etc/dnsmasq.d/netwatch.conf and a dnsmasq drop-in, downloads the first
# blocklist, opens port 53 in ufw for NETWATCH_DNS_ALLOW_FROM only, and checks the result with
# `netwatch dns check`. When NETWATCH_DISCOVERY_INTERFACE is set, it installs the IEEE MAC address
# registry (ieee-data) if needed, enables the five-minute ARP scan and runs the first scan, which
# records the devices on the LAN as the baseline. uninstall.sh reverses all of it.

set -euo pipefail

REPO_URL="${NETWATCH_REPO_URL:-https://github.com/iMovingTarget/netwatch.git}"
PREFIX=/opt/netwatch
CONF_DIR=/etc/netwatch
UNIT_DIR=/etc/systemd/system
SERVICE_USER=netwatch
KEEP_RELEASES=3
BLOCKLIST_DIR=/var/lib/netwatch-blocklist
DNSMASQ_CONF=/etc/dnsmasq.d/netwatch.conf
DNSMASQ_DROPIN_DIR=$UNIT_DIR/dnsmasq.service.d
# The same conf-dir rule the dnsmasq package uses (CONFIG_DIR in /etc/default/dnsmasq).
DNSMASQ_CONFIG_DIR=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new
UFW_COMMENT="netwatch dns"

log() { printf 'install: %s\n' "$*"; }
warn() { printf 'install: warning: %s\n' "$*" >&2; }
die() {
    printf 'install: error: %s\n' "$*" >&2
    exit 1
}

# The value of a setting in netwatch.env (last one wins), without quotes; commas become spaces.
setting() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONF_DIR/netwatch.env" |
        tail -n 1 | sed -e "s/^[\"']//" -e "s/[\"'][[:space:]]*$//" -e 's/[[:space:]]*$//' |
        tr ',' ' '
}

# Delete every ufw rule this script added, highest number first so the numbers stay valid.
remove_ufw_rules() {
    command -v ufw >/dev/null || return 0
    ufw status numbered | sed -n "s/^\[ *\([0-9][0-9]*\)\].*# $UFW_COMMENT\$/\1/p" |
        sort -rn | while read -r number; do
            ufw --force delete "$number" >/dev/null
        done
}

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
[ $# -eq 1 ] || die "usage: install.sh <git-ref>   (a tag, branch or commit, e.g. v0.1.0)"
ref=$1
case $ref in
-*) die "invalid ref '$ref'" ;;
esac

for cmd in git python3 systemctl useradd; do
    command -v "$cmd" >/dev/null || die "$cmd not found"
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' ||
    die "Python 3.12 or newer is required, found $(python3 --version 2>&1)"
python3 -c 'import ensurepip' 2>/dev/null ||
    die "python3-venv is missing: sudo apt install python3-venv"

work=$(mktemp -d)
release=""
cleanup() {
    rm -rf "$work"
    # A release directory without the completion marker is a failed build: remove it.
    if [ -n "$release" ] && [ ! -e "$release/.complete" ]; then
        rm -rf "$release"
    fi
}
trap cleanup EXIT

# 1. Fetch the source and resolve the ref to one commit.
log "fetching $ref from $REPO_URL"
git clone --quiet --no-checkout "$REPO_URL" "$work/src"
revision=""
for candidate in "refs/tags/$ref" "refs/remotes/origin/$ref" "$ref"; do
    if revision=$(git -C "$work/src" rev-parse --verify --quiet "$candidate^{commit}"); then
        break
    fi
done
[ -n "$revision" ] || die "no tag, branch or commit named '$ref' in $REPO_URL"
git -C "$work/src" checkout --quiet --detach "$revision"
log "resolved $ref to $revision"

# 2. Build the release, unless this exact commit was already built completely.
release="$PREFIX/releases/$revision"
if [ -e "$release/.complete" ]; then
    log "reusing the existing build in $release"
else
    log "building $release"
    rm -rf "$release"
    mkdir -p "$PREFIX/releases"
    python3 -m venv "$release/venv" || die "could not create a virtualenv in $release"
    "$release/venv/bin/pip" install --quiet --disable-pip-version-check --no-cache-dir \
        "$work/src" || die "building $ref failed (pip output above); nothing was changed"
    touch "$release/.complete"
fi
printf 'NETWATCH_REVISION=%s\nNETWATCH_REF=%s\n' "$revision" "$ref" >"$release/revision.env"
version=$(NETWATCH_REVISION=$revision "$release/venv/bin/netwatch" --version) ||
    die "smoke test failed: $release/venv/bin/netwatch --version"
log "smoke test: $version"

# 3. Service user and configuration.
if ! getent passwd "$SERVICE_USER" >/dev/null; then
    log "creating system user $SERVICE_USER"
    useradd --system --user-group --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONF_DIR"
if [ -e "$CONF_DIR/netwatch.env" ]; then
    log "keeping the existing $CONF_DIR/netwatch.env"
    # It may hold secrets, and the CLI reads it as the netwatch user.
    chown root:"$SERVICE_USER" "$CONF_DIR/netwatch.env"
    chmod 0640 "$CONF_DIR/netwatch.env"
else
    install -m 0640 -o root -g "$SERVICE_USER" \
        "$work/src/deploy/netwatch.env.example" "$CONF_DIR/netwatch.env"
    log "created $CONF_DIR/netwatch.env from the example"
fi
if [ ! -e "$CONF_DIR/allowlist.txt" ]; then
    install -m 0640 -o root -g "$SERVICE_USER" \
        "$work/src/deploy/allowlist.txt.example" "$CONF_DIR/allowlist.txt"
fi
install -m 0755 "$work/src/deploy/bin/netwatch" /usr/local/bin/netwatch

# 4. Switch to the new release. rename(2) is atomic, so `current` is never missing or half-written.
previous=$(readlink "$PREFIX/current" 2>/dev/null || true)
ln -sfn "releases/$revision" "$PREFIX/current.new"
mv -T "$PREFIX/current.new" "$PREFIX/current"

# 5. Units: install what this commit ships, remove netwatch units it no longer ships.
shipped=()
for unit in "$work/src/deploy/systemd/"netwatch*.service "$work/src/deploy/systemd/"netwatch*.timer; do
    [ -e "$unit" ] || continue
    install -m 0644 "$unit" "$UNIT_DIR/"
    shipped+=("$(basename "$unit")")
done
for installed in "$UNIT_DIR"/netwatch*.service "$UNIT_DIR"/netwatch*.timer; do
    [ -e "$installed" ] || continue
    name=$(basename "$installed")
    if ! printf '%s\n' "${shipped[@]}" | grep -qxF "$name"; then
        log "removing $name, which this release no longer ships"
        systemctl disable --now --quiet "$name" || true
        rm -f "$installed"
    fi
done
systemctl daemon-reload

# 6. DNS: dnsmasq answers queries; Netwatch configures it, feeds it the blocklist and reads its log.
dns_listen=$(setting NETWATCH_DNS_LISTEN)
if [ -z "$dns_listen" ]; then
    log "NETWATCH_DNS_LISTEN is not set in $CONF_DIR/netwatch.env: skipping the DNS setup"
else
    log "setting up dnsmasq on $dns_listen"
    install -d -m 0755 -o "$SERVICE_USER" -g "$SERVICE_USER" "$BLOCKLIST_DIR"
    install -d -m 0755 "$DNSMASQ_DROPIN_DIR" /etc/dnsmasq.d
    install -m 0644 "$work/src/deploy/systemd/dnsmasq.service.d/netwatch.conf" \
        "$DNSMASQ_DROPIN_DIR/netwatch.conf"
    systemctl daemon-reload
    # Write the configuration before installing the package, so dnsmasq's first start already
    # uses it instead of trying to take port 53 on every interface.
    [ -e "$DNSMASQ_CONF" ] && cp -p "$DNSMASQ_CONF" "$work/dnsmasq.conf.previous"
    "$release/venv/bin/netwatch" dns config >"$work/netwatch.conf" ||
        die "netwatch dns config failed (see above)"
    install -m 0644 "$work/netwatch.conf" "$DNSMASQ_CONF"
    if ! dpkg-query -W -f '${Status}' dnsmasq 2>/dev/null | grep -q 'ok installed'; then
        log "installing dnsmasq"
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y -q dnsmasq >/dev/null ||
            { apt-get update -q >/dev/null && apt-get install -y -q dnsmasq >/dev/null; } ||
            die "could not install dnsmasq"
    fi
    if ! dnsmasq --test -7 "$DNSMASQ_CONFIG_DIR" >"$work/dnsmasq-test.txt" 2>&1; then
        cat "$work/dnsmasq-test.txt" >&2
        if [ -e "$work/dnsmasq.conf.previous" ]; then
            cp -p "$work/dnsmasq.conf.previous" "$DNSMASQ_CONF"
        else
            rm -f "$DNSMASQ_CONF"
        fi
        die "dnsmasq rejected the configuration; the previous one was restored"
    fi
    if [ ! -e "$BLOCKLIST_DIR/blocklist.hosts" ]; then
        log "downloading the first blocklist"
        systemctl start netwatch-blocklist.service ||
            warn "the blocklist download failed; DNS works without blocking until the timer" \
                "retries (journalctl -u netwatch-blocklist)"
    fi
    systemctl enable --quiet dnsmasq.service
    systemctl restart dnsmasq.service || die "dnsmasq did not start (journalctl -u dnsmasq)"

    # Firewall: port 53 from the configured networks to the listen addresses only.
    if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
        remove_ufw_rules
        allow_from=$(setting NETWATCH_DNS_ALLOW_FROM)
        if [ -z "$allow_from" ]; then
            warn "NETWATCH_DNS_ALLOW_FROM is empty: no ufw rule added, so other devices" \
                "cannot reach DNS on this host"
        fi
        for network in $allow_from; do
            for address in $dns_listen; do
                for proto in udp tcp; do
                    ufw allow proto "$proto" from "$network" to "$address" port 53 \
                        comment "$UFW_COMMENT" >/dev/null
                done
                log "ufw: allowed DNS from $network to $address"
            done
        done
    fi
fi

# 7. LAN device discovery: an ARP scan every five minutes, only if an interface is configured.
discovery_interface=$(setting NETWATCH_DISCOVERY_INTERFACE)
if [ -z "$discovery_interface" ]; then
    log "NETWATCH_DISCOVERY_INTERFACE is not set in $CONF_DIR/netwatch.env: device discovery is off"
    systemctl disable --now --quiet netwatch-discovery.timer 2>/dev/null || true
elif ! dpkg-query -W -f '${Status}' ieee-data 2>/dev/null | grep -q 'ok installed'; then
    log "installing ieee-data (the IEEE MAC address registry, for device vendors)"
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -q ieee-data >/dev/null ||
        { apt-get update -q >/dev/null && apt-get install -y -q ieee-data >/dev/null; } ||
        warn "could not install ieee-data: devices are recorded without a vendor"
fi

# 8. (Re)start everything that has an [Install] section; timer-driven services start on schedule.
started=()
for name in "${shipped[@]}"; do
    grep -q '^\[Install\]' "$UNIT_DIR/$name" || continue
    if [ "$name" = netwatch-discovery.timer ] && [ -z "$discovery_interface" ]; then
        continue
    fi
    systemctl enable --quiet "$name"
    systemctl restart "$name"
    started+=("$name")
done
sleep 2
for name in "${started[@]}"; do
    if ! systemctl is-active --quiet "$name"; then
        systemctl status --no-pager --lines=20 "$name" || true
        rollback_hint=""
        if [ -n "$previous" ]; then
            rollback_hint=" Roll back with: sudo $0 ${previous##*/}"
        fi
        die "$name did not start.$rollback_hint"
    fi
done

if [ -n "$dns_listen" ]; then
    "$release/venv/bin/netwatch" dns check ||
        warn "the DNS check failed: see the lines above and journalctl -u dnsmasq"
fi

# The first scan now rather than within five minutes: it records the baseline, and a wrong
# interface name shows up here instead of in a timer failing quietly.
if [ -n "$discovery_interface" ]; then
    log "scanning the LAN on $discovery_interface"
    if ! systemctl start netwatch-discovery.service; then
        journalctl -u netwatch-discovery.service -n 5 --no-pager -o cat >&2 || true
        die "the device scan failed (see above; journalctl -u netwatch-discovery)"
    fi
    # As the netwatch user, like /usr/local/bin/netwatch, so nothing in the state directory
    # becomes root's. The first line is "last scan <time>: N of N devices answered".
    inventory=$(runuser -u "$SERVICE_USER" -- "$release/venv/bin/netwatch" devices) || true
    log "${inventory%%$'\n'*}"
fi

# 9. Keep the newest few releases, never the active one.
find "$PREFIX/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' |
    sort -rn | awk -v keep="$KEEP_RELEASES" 'NR > keep { print $2 }' |
    while read -r old; do
        [ "$old" = "$revision" ] || rm -rf "${PREFIX:?}/releases/$old"
    done

log "installed $version from $ref"
for name in "${started[@]}"; do
    log "  $name: $(systemctl is-active "$name")"
done
log "logs: journalctl -u 'netwatch*' -n 50"
