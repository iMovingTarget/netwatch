#!/usr/bin/env bash
# Read-only readiness report for a Netwatch host.
#
# Prints what Netwatch depends on: OS and Python versions, network setup, who holds port 53,
# how the host itself resolves names, where sshd logs go, firewall state and pending updates.
# It changes nothing. Run it with sudo for the full picture; without root, the socket owner,
# sshd, firewall and journal sections are partial.
#
# Usage: sudo bash check-host.sh > netwatch-check.txt 2>&1
#
# Sourcing the file defines the helper functions without running the report (used by the tests).

set -o pipefail
export LC_ALL=C

CHECK_VERSION=1

# Effective systemd-resolved stub listener setting under the root directory $1.
# grep exits 2 when one of the paths is missing (the drop-in directory usually is) even if it
# matched in the other, so decide on its output, not on its exit code.
stub_listener_setting() {
    local root=${1:-} found
    found=$(grep -rHs "^[^#]*DNSStubListener" "$root/etc/systemd/resolved.conf" \
        "$root/etc/systemd/resolved.conf.d/")
    printf '%s\n' "${found:-DNSStubListener not set (default: yes)}"
}

# Active (non-comment, non-blank) lines of each config file given.
show_config_files() {
    grep -Hv -e "^[[:space:]]*#" -e "^[[:space:]]*$" "$@"
}

export -f stub_listener_setting show_config_files

section() {
    printf '\n===== %s\n' "$1"
}

# Print a shell command, run it, and report a non-zero exit code instead of stopping,
# so one missing tool never hides the rest of the report.
run() {
    printf '$ %s\n' "$1"
    bash -c "$1" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '[exit %d]\n' "$rc"
    fi
}

main() {
    section "meta"
    printf 'check-host version %s\n' "$CHECK_VERSION"
    run 'date -Is'
    run 'hostname'
    if [ "$(id -u)" -eq 0 ]; then
        echo "running as root (invoked by ${SUDO_USER:-root})"
    else
        echo "NOT running as root: some sections are partial"
    fi

    section "os"
    run 'grep -E "^(PRETTY_NAME|VERSION_ID|VERSION_CODENAME)=" /etc/os-release'
    run 'uname -r'
    run 'uptime -p'
    run 'systemd-detect-virt'
    run 'systemctl --version | head -n 1'
    run 'systemctl is-active hv-kvp-daemon.service'

    section "resources"
    run 'nproc'
    run 'free -m'
    run 'swapon --show'
    run 'df -h / /var'
    run 'lsmod | grep -E "^hv_" || echo "no hv_ modules loaded"'

    section "python"
    run 'python3 --version'
    run 'python3 -c "import venv, ensurepip; print(\"venv and ensurepip available\")"'
    run 'dpkg-query -W python3 python3-venv python3-pip'

    section "network"
    run 'ip -br link'
    run 'ip -br addr'
    run 'ip route'
    run 'ip -6 route'
    run 'ls -l /etc/netplan/'
    run 'cat /etc/netplan/*.yaml'

    section "name resolution of the host itself"
    run 'ls -l /etc/resolv.conf'
    run 'grep -v "^#" /etc/resolv.conf'
    run 'resolvectl dns; resolvectl domain'
    run 'stub_listener_setting'
    run 'getent ahostsv4 github.com | head -n 2'

    section "port 53 and resolvers"
    run 'ss -lntup "( sport = :53 )"'
    run 'dpkg-query -W dnsmasq dnsmasq-base unbound bind9'
    run 'systemctl is-enabled dnsmasq.service; systemctl is-active dnsmasq.service'
    run 'show_config_files /etc/dnsmasq.conf /etc/dnsmasq.d/*'
    run 'grep -v -e "^#" -e "^$" /etc/default/dnsmasq'
    run 'journalctl -u dnsmasq.service -n 15 --no-pager -o short-iso'
    if command -v dig >/dev/null 2>&1; then
        for addr in 127.0.0.1 $(ip -4 -o addr show scope global | awk '{split($4, a, "/"); print a[1]}'); do
            run "dig +time=2 +tries=1 +short example.com @${addr}"
        done
    else
        echo "dig not installed (package: bind9-dnsutils)"
    fi

    section "sshd and auth logging"
    run 'systemctl is-active ssh.socket ssh.service'
    run 'sshd -T | grep -E "^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|maxauthtries) "'
    run 'systemctl is-active rsyslog.service'
    run 'ls -l --time-style=long-iso /var/log/auth.log'
    run 'tail -n 3 /var/log/auth.log'
    run 'journalctl -t sshd -t sshd-session -n 5 --no-pager -o short-iso'

    section "firewall"
    run 'ufw status verbose'

    section "updates"
    run 'ls -l --time-style=long-iso /var/lib/apt/periodic/update-success-stamp /var/cache/apt/pkgcache.bin'
    run 'apt-get -s -o Debug::NoLocking=1 upgrade | grep -c "^Inst"'
    run 'systemctl is-enabled unattended-upgrades.service; systemctl is-active unattended-upgrades.service'
    run 'cat /var/run/reboot-required 2>/dev/null || echo "no reboot required"'

    section "time"
    run 'timedatectl show -p Timezone -p NTP -p NTPSynchronized'

    section "tools"
    for tool in git curl dig arping nmap sqlite3 make; do
        printf '%-8s %s\n' "$tool" "$(command -v "$tool" || echo MISSING)"
    done

    section "leftovers from earlier attempts"
    run 'getent passwd netwatch netmon || echo "no netwatch or netmon user"'
    run 'systemctl list-unit-files --no-pager "netwatch*" "netmon*" "gunicorn*"'
    run 'ls -ld /opt/netwatch /opt/netmon /etc/netwatch /etc/netmon /var/lib/netwatch /var/lib/netmon'
    owner_home="$(getent passwd "${SUDO_USER:-$(id -un)}" | cut -d: -f6)"
    run "ls -la '${owner_home}'"

    section "end"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
