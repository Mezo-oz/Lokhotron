#!/usr/bin/env bash
# Phase 1 step-0 real-veth calibration.
#
# Stands up two network namespaces joined by a veth pair, runs the echo server on one side
# and the probe on the other, and injects each verdict with tc/nftables so the classifier
# can be checked against KNOWN ground truth on real kernel path — the safety net that lets
# you trust a live delta later (you can't tell a capture bug from a finding on the wire).
#
# Status: the clean case and the UDP silent-drop case run today. The RST and throttle cases
# are stubbed pending the TCP-handshake probe (see STATUS.md / ECHO.md §7); their nftables /
# tc recipes are noted inline so they're ready to enable the moment the probe lands.
#
# Requires root (CAP_NET_ADMIN) and a kernel with netns + veth. Verified target: WSL2.
set -euo pipefail

NS_A=lok_sensor   # RU-side sensor
NS_B=lok_server   # non-RU echo server
VETH_A=lokveth0
VETH_B=lokveth1
IP_A=10.77.0.1
IP_B=10.77.0.2
PORT=47017

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root (CAP_NET_ADMIN needed)"; exit 1; }; }

cleanup() {
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
}

setup() {
    cleanup
    ip netns add "$NS_A"
    ip netns add "$NS_B"
    ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" netns "$NS_B"
    ip -n "$NS_A" addr add "$IP_A/24" dev "$VETH_A"
    ip -n "$NS_B" addr add "$IP_B/24" dev "$VETH_B"
    ip -n "$NS_A" link set "$VETH_A" up
    ip -n "$NS_B" link set "$VETH_B" up
    ip -n "$NS_A" link set lo up
    ip -n "$NS_B" link set lo up
}

# Run one case: $1=label, $2=drop_after (empty for clean), $3=expected_kind
run_case() {
    local label="$1" drop_after="${2:-}" expect="$3"
    echo "--- case: $label (expect $expect) ---"
    ip netns exec "$NS_B" ./target/debug/echo-server "$IP_B:$PORT" $drop_after &
    local srv=$!
    sleep 0.3
    local out
    out=$(ip netns exec "$NS_A" ./target/debug/probe "$IP_B:$PORT" 8 || true)
    kill "$srv" 2>/dev/null || true
    echo "  probe -> $out"
    if echo "$out" | grep -q "\"kind\":\"$expect\""; then
        echo "  PASS"
    else
        echo "  FAIL (wanted kind=$expect)"; return 1
    fi
}

main() {
    need_root
    [ -x ./target/debug/probe ] || { echo "build first: cargo build --workspace"; exit 1; }
    trap cleanup EXIT
    setup

    run_case "clean path"       ""  "ok"
    run_case "drop from marker 4" "4" "silent_drop_from_segment"

    # STUBBED until the TCP-handshake probe lands (ECHO.md §7):
    #   RST injection:  ip netns exec $NS_B nft add rule ip filter input tcp dport $PORT reject with tcp reset
    #                   -> expect injected_rst_at_sni (needs lok-capture wired + a distinct TTL)
    #   Throttle:       ip netns exec $NS_B tc qdisc add dev $VETH_B root tbf rate 128kbit burst 4k latency 50ms
    #                   -> expect throttle_to_rate (needs the bulk-throughput phase)
    echo "(RST + throttle cases stubbed pending the TCP probe)"

    echo "calibration: OK"
}

main "$@"
