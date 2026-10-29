#!/usr/bin/env bash
# CI only: plug a fake device into the test bridge nwbr0. It lives in its own network namespace
# and answers ARP like any host.  Usage: sudo .github/fake-device.sh NAME IPV4 MAC
set -euo pipefail
name=$1 address=$2 mac=$3
ip netns add "$name"
ip link add "v-$name" type veth peer name eth0 netns "$name"
ip link set "v-$name" master nwbr0 up
ip -n "$name" link set eth0 address "$mac"
ip -n "$name" addr add "$address/24" dev eth0
ip -n "$name" link set eth0 up
