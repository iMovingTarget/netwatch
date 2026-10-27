#!/usr/bin/env bash
# Remove Netwatch from this host.
#
#   sudo ./uninstall.sh           stop and remove the services and code; keep settings and data
#   sudo ./uninstall.sh --purge   also remove /etc/netwatch, /var/lib/netwatch and the netwatch user

set -euo pipefail

PREFIX=/opt/netwatch
CONF_DIR=/etc/netwatch
STATE_DIR=/var/lib/netwatch
UNIT_DIR=/etc/systemd/system
SERVICE_USER=netwatch

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
systemctl daemon-reload
systemctl reset-failed 'netwatch*' 2>/dev/null || true

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
