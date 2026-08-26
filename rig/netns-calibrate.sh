#!/usr/bin/env bash
# Phase 1 step-0 real-veth calibration.
#
# Stands up two network namespaces joined by a veth pair, runs the echo server on one side
# and the probe on the other, and injects each verdict with tc/nftables so the classifier
# can be checked against KNOWN ground truth on real kernel path — the safety net that lets
# you trust a live delta later (you can't tell a capture bug from a finding on the wire).
#
# Status: clean, UDP silent-drop, throttle, and injected-RST cases all run today. The battery
# measures real TCP reachability + throughput, and (Linux+root) runs an AF_PACKET capture
# during the handshake so a reset with an anomalous TTL is recovered as injected_rst_at_sni.
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

    run_case "clean path"         ""  "ok"
    run_case "drop from marker 4" "4" "silent_drop_from_segment"

    # Throttle: rate-limit the server's egress so the TCP bulk-echo comes back far below
    # EXPECTED_BPS. The battery measures the real rate and classifies throttle_to_rate.
    echo "--- case: throttle to 128kbit (expect throttle_to_rate) ---"
    ip netns exec "$NS_B" tc qdisc add dev "$VETH_B" root tbf rate 128kbit burst 4kb latency 50ms
    ip netns exec "$NS_B" ./target/debug/echo-server "$IP_B:$PORT" &
    srv=$!; sleep 0.3
    out=$(ip netns exec "$NS_A" ./target/debug/probe "$IP_B:$PORT" 8 || true)
    kill "$srv" 2>/dev/null || true
    ip netns exec "$NS_B" tc qdisc del dev "$VETH_B" root 2>/dev/null || true
    echo "  probe -> $out"
    echo "$out" | grep -q '"kind":"throttle_to_rate"' && echo "  PASS" || { echo "  FAIL"; exit 1; }

    # Injected RST: no TCP listener on the server side, so a connect is refused with a RST;
    # mangle that RST's TTL to 200 (distinct from the 1-hop path's ~64) so is_ttl_anomalous()
    # fires. The battery's AF_PACKET capture on the sensor side recovers it. Requires nftables.
    echo "--- case: injected RST with anomalous TTL (expect injected_rst_at_sni) ---"
    ip netns exec "$NS_B" nft -f - <<NFT
table ip lok {
    chain out {
        type filter hook output priority mangle;
        tcp sport $PORT tcp flags rst ip ttl set 200
    }
}
NFT
    # UDP echo only (LOK_NO_TCP); TCP has no listener -> connect refused -> mangled RST.
    ip netns exec "$NS_B" env LOK_NO_TCP=1 ./target/debug/echo-server "$IP_B:$PORT" 2>/dev/null &
    srv=$!; sleep 0.3
    # probe runs the battery; capture needs root, which we have inside the rig.
    out=$(ip netns exec "$NS_A" ./target/debug/probe "$IP_B:$PORT" 8 || true)
    kill "$srv" 2>/dev/null || true
    ip netns exec "$NS_B" nft delete table ip lok 2>/dev/null || true
    echo "  probe -> $out"
    echo "$out" | grep -q '"kind":"injected_rst_at_sni"' && echo "  PASS" || { echo "  FAIL"; exit 1; }

    echo "calibration: OK"
}

main "$@"
