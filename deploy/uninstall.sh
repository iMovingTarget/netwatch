#!/usr/bin/env bash
# Remove Netwatch from this host.
#
#   sudo ./uninstall.sh           stop and remove the services and code; keep settings and data
#   sudo ./uninstall.sh --purge   also remove /etc/netwatch, /var/lib/netwatch and the netwatch user
#
# If Netwatch set up DNS, this stops dnsmasq and removes Netwatch's dnsmasq configuration and
# firewall rules. Switch every device that uses this host for DNS back first (docs/rollback.md).

set -euo pipefail

PREFIX=/opt/netwatch
CONF_DIR=/etc/netwatch
STATE_DIR=/var/lib/netwatch
UNIT_DIR=/etc/systemd/system
SERVICE_USER=netwatch
BLOCKLIST_DIR=/var/lib/netwatch-blocklist
DNSMASQ_CONF=/etc/dnsmasq.d/netwatch.conf
DNSMASQ_DROPIN=$UNIT_DIR/dnsmasq.service.d/netwatch.conf
UFW_COMMENT="netwatch dns"

log() { printf 'uninstall: %s\n' "$*"; }
die() {
    printf 'uninstall: error: %s\n' "$*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
purge=false
case "${1:-}" in
"") ;;
--purge) purge=true ;;
*) die "usage: uninstall.sh [--purge]" ;;
esac

for unit in "$UNIT_DIR"/netwatch*.service "$UNIT_DIR"/netwatch*.timer; do
    [ -e "$unit" ] || continue
    name=$(basename "$unit")
    log "stopping and removing $name"
    systemctl disable --now --quiet "$name" || true
    rm -f "$unit"
done
if [ -e "$DNSMASQ_CONF" ] || [ -e "$DNSMASQ_DROPIN" ]; then
    # Netwatch configured dnsmasq; without that configuration it would fall back to the
    # package defaults (answering on every interface), so stop it rather than restart it.
    log "stopping dnsmasq and removing Netwatch's dnsmasq configuration"
    systemctl disable --now --quiet dnsmasq.service || true
    rm -f "$DNSMASQ_CONF" "$DNSMASQ_DROPIN"
    rmdir --ignore-fail-on-non-empty "$(dirname "$DNSMASQ_DROPIN")" 2>/dev/null || true
fi
if command -v ufw >/dev/null; then
    ufw status numbered | sed -n "s/^\[ *\([0-9][0-9]*\)\].*# $UFW_COMMENT\$/\1/p" |
        sort -rn | while read -r number; do
            ufw --force delete "$number" >/dev/null
            log "removed ufw rule $number ($UFW_COMMENT)"
        done
fi
systemctl daemon-reload
systemctl reset-failed 'netwatch*' 2>/dev/null || true
rm -rf "$BLOCKLIST_DIR"
rm -f /usr/local/bin/netwatch

if [ -e "$PREFIX" ]; then
    log "removing $PREFIX"
    rm -rf "$PREFIX"
fi

if $purge; then
    log "removing $CONF_DIR and $STATE_DIR"
    rm -rf "$CONF_DIR" "$STATE_DIR"
    if getent passwd "$SERVICE_USER" >/dev/null; then
        log "removing user $SERVICE_USER"
        userdel "$SERVICE_USER"
    fi
else
    log "kept $CONF_DIR, $STATE_DIR and the $SERVICE_USER user (use --purge to remove them)"
fi
log "done"
