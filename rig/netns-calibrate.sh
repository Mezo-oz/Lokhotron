#!/usr/bin/env bash
# Phase 1 step-0 real-veth calibration.
#
# Stands up two network namespaces joined by a veth pair, runs the echo server on one side
# and the probe on the other, and injects each verdict with tc/nftables so the classifier
# can be checked against KNOWN ground truth on real kernel path — the safety net that lets
# you trust a live delta later (you can't tell a capture bug from a finding on the wire).
#
# Status: eight cases run today — clean, UDP silent-drop, throttle, injected-RST, in-flight
# payload mutation, a negative case proving a foreign RST does NOT contaminate a clean
# verdict, an in-flight rewrite of the probe's own header, and a reflector that bounces the
# probe back instead of delivering it. The battery measures real TCP reachability +
# throughput, and (Linux+root) runs an AF_PACKET capture during the handshake so a reset
# with an anomalous TTL is recovered as injected_rst_at_sni. Every capture is scoped to the
# probe's own 5-tuple, which is what the sixth case exists to prove on the wire rather than
# only in unit tests.
#
# The last two cases are the keyed wire format's (lok-wire): both are shapes that produced a
# WRONG verdict before it — a header rewrite read as a drop that never happened, and a
# reflector read as a healthy path.
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

# Shared secret for the keyed datagram format, inherited by every `ip netns exec` below.
# A fixed value on purpose: this is a lab rig, so runs should be byte-reproducible, and a
# published key is exactly right for a namespace no adversary is on. Real deployments
# generate their own — see deploy/DEPLOY.md.
export LOK_PROBE_KEY=7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c

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

    # Payload mutated in flight: nftables rewrites one byte of the echo's known payload on
    # the server's egress (and fixes the UDP checksum itself, exactly as a real middlebox
    # must). Every marker still arrives, so only the sent-vs-returned byte comparison can
    # see it — this is the case that separates payload_mutated from a drop verdict.
    # @th,320,8 = 8 bits at bit 320 from the UDP header = UDP payload byte 32 (the header is
    # 8 bytes = 64 bits), i.e. the first byte of the keyed payload block, which starts after
    # [nonce][marker][session][session_tag][leg_tag].
    echo "--- case: payload mutated in flight (expect payload_mutated) ---"
    ip netns exec "$NS_B" nft -f - <<NFT
table ip lokmut {
    chain out {
        type filter hook output priority mangle;
        udp sport $PORT @th,320,8 set 0xff
    }
}
NFT
    ip netns exec "$NS_B" ./target/debug/echo-server "$IP_B:$PORT" &
    srv=$!; sleep 0.3
    out=$(ip netns exec "$NS_A" ./target/debug/probe "$IP_B:$PORT" 8 || true)
    kill "$srv" 2>/dev/null || true
    ip netns exec "$NS_B" nft delete table ip lokmut 2>/dev/null || true
    echo "  probe -> $out"
    echo "$out" | grep -q '"kind":"payload_mutated"' && echo "  PASS" || { echo "  FAIL"; exit 1; }

    # Negative case — the shared-vantage false positive. A second flow to a closed port on the
    # same server answers with RSTs whose TTL is mangled to 200, i.e. RSTs that WOULD read as
    # injected if the capture matched them. They belong to a different 5-tuple, so the probe
    # must ignore them and still call the (genuinely clean) measured path ok. Before the flow
    # filter this case reported injected_rst_at_sni on a healthy path.
    echo "--- case: foreign RST on another flow (expect ok, not injected_rst_at_sni) ---"
    ip netns exec "$NS_B" nft -f - <<NFT
table ip lokrst {
    chain out {
        type filter hook output priority mangle;
        tcp sport 9999 tcp flags rst ip ttl set 200
    }
}
NFT
    ip netns exec "$NS_B" ./target/debug/echo-server "$IP_B:$PORT" &
    srv=$!
    # Noise generator: repeatedly hit a closed port so the server keeps emitting mangled RSTs
    # across the probe's capture window. Paced, so it doesn't skew the throughput measurement.
    ip netns exec "$NS_A" bash -c "while :; do (exec 3<>/dev/tcp/$IP_B/9999) 2>/dev/null; sleep 0.05; done" &
    noise=$!
    sleep 0.3
    out=$(ip netns exec "$NS_A" ./target/debug/probe "$IP_B:$PORT" 8 || true)
    kill "$noise" 2>/dev/null || true
    kill "$srv" 2>/dev/null || true
    ip netns exec "$NS_B" nft delete table ip lokrst 2>/dev/null || true
    echo "  probe -> $out"
    echo "$out" | grep -q '"kind":"ok"' && echo "  PASS" || { echo "  FAIL (a foreign flow's RST leaked into the verdict)"; exit 1; }

    # The probe's OWN header rewritten in flight. @th,96,8 = UDP payload byte 4 = the high
    # byte of the marker. Before the keyed format this made the echo unrecognizable and the
    # run reported silent_drop_from_segment{n:0} — a fabricated block on a path that
    # delivered all eight datagrams. The keyed payload still names each one, so the rewrite
    # now reads as what it is.
    echo "--- case: probe header rewritten in flight (expect payload_mutated, NOT a drop) ---"
    ip netns exec "$NS_B" nft -f - <<NFT
table ip lokhdr {
    chain out {
        type filter hook output priority mangle;
        udp sport $PORT @th,96,8 set 0xff
    }
}
NFT
    ip netns exec "$NS_B" ./target/debug/echo-server "$IP_B:$PORT" &
    srv=$!; sleep 0.3
    out=$(ip netns exec "$NS_A" ./target/debug/probe "$IP_B:$PORT" 8 || true)
    kill "$srv" 2>/dev/null || true
    ip netns exec "$NS_B" nft delete table ip lokhdr 2>/dev/null || true
    echo "  probe -> $out"
    if echo "$out" | grep -q '"kind":"payload_mutated"'; then
        echo "  PASS"
    else
        echo "  FAIL (a rewritten header must not be reported as a drop)"; exit 1
    fi

    # A middlebox that swallows the traffic and bounces the probe's own datagrams back,
    # trying to make a dead path look healthy. `reflect` returns the request byte for byte,
    # with no response tag — which is all an on-path device without the key can do. The
    # probe must refuse to score any of it as an arrival. Before the keyed format this read
    # as ok: every marker "arrived", so the verdict was a clean path.
    echo "--- case: reflector fakes delivery (expect udp_class_drop, NOT ok) ---"
    ip netns exec "$NS_B" ./target/debug/echo-server "$IP_B:$PORT" reflect &
    srv=$!; sleep 0.3
    out=$(ip netns exec "$NS_A" ./target/debug/probe "$IP_B:$PORT" 8 || true)
    kill "$srv" 2>/dev/null || true
    echo "  probe -> $out"
    if echo "$out" | grep -q '"kind":"udp_class_drop"'; then
        echo "  PASS"
    else
        echo "  FAIL (a reflected request was scored as delivery)"; exit 1
    fi

    echo "calibration: OK"
}

main "$@"
