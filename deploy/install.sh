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

set -euo pipefail

REPO_URL="${NETWATCH_REPO_URL:-https://github.com/iMovingTarget/netwatch.git}"
PREFIX=/opt/netwatch
CONF_DIR=/etc/netwatch
UNIT_DIR=/etc/systemd/system
SERVICE_USER=netwatch
KEEP_RELEASES=3

log() { printf 'install: %s\n' "$*"; }
die() {
    printf 'install: error: %s\n' "$*" >&2
    exit 1
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
else
    install -m 0640 -o root -g "$SERVICE_USER" \
        "$work/src/deploy/netwatch.env.example" "$CONF_DIR/netwatch.env"
    log "created $CONF_DIR/netwatch.env from the example"
fi

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

# 6. (Re)start everything that has an [Install] section; timer-driven services start on schedule.
started=()
for name in "${shipped[@]}"; do
    grep -q '^\[Install\]' "$UNIT_DIR/$name" || continue
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

# 7. Keep the newest few releases, never the active one.
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
