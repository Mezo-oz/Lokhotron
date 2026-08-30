#!/usr/bin/env bash
# Run the workspace test suite inside a private network namespace.
#
# The loopback calibration cases (real probe against a real echo server on 127.0.0.1) are
# the ones that prove the probe and the classifier agree on ground truth, so they must not
# be the ones you skip when the host's loopback is unusable. Some WSL networking modes
# swallow IPv4 loopback UDP specifically — TCP to 127.0.0.1 works, `::1` works, UDP to
# 127.0.0.1 vanishes — which fails every UDP case for a reason that has nothing to do with
# the code. A private netns gets its own real loopback and sidesteps the question.
#
# Root is needed only to create the namespace. cargo is not usually on root's PATH, so the
# build step runs as the invoking user's cargo; override with CARGO=/path/to/cargo.
#
#   cd /mnt/x/Lokhotron && sudo bash rig/netns-test.sh
#   wsl -d Ultramarine -u root -- bash -c 'bash //mnt/x/Lokhotron/rig/netns-test.sh'
set -uo pipefail

NS=lok_test
ARGS=("$@")

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run as root (CAP_NET_ADMIN needed to create a netns)"; exit 1; }; }

# Locate cargo, and point rustup at the toolchain that owns it. Running as root otherwise
# resolves RUSTUP_HOME to /root/.rustup, where no default toolchain is configured — the
# rustup shim then refuses to pick one and the build fails for a reason that looks nothing
# like the real cause. Sets CARGO_BIN in the caller's shell (not a subshell), because the
# environment it exports is the point.
CARGO_BIN=""
find_cargo() {
    if [ -n "${CARGO:-}" ] && [ -x "$CARGO" ]; then CARGO_BIN="$CARGO"; return; fi
    if CARGO_BIN=$(command -v cargo 2>/dev/null); then return; fi
    for home in "${SUDO_USER:+/home/$SUDO_USER}" "$(getent passwd 1000 | cut -d: -f6)"; do
        if [ -n "$home" ] && [ -x "$home/.cargo/bin/cargo" ]; then
            export CARGO_HOME="${CARGO_HOME:-$home/.cargo}"
            [ -d "$home/.rustup" ] && export RUSTUP_HOME="${RUSTUP_HOME:-$home/.rustup}"
            CARGO_BIN="$home/.cargo/bin/cargo"
            return
        fi
    done
    CARGO_BIN=""
}

main() {
    need_root
    cd "$(dirname "$0")/.." || exit 1

    find_cargo
    [ -n "$CARGO_BIN" ] || { echo "cargo not found; set CARGO=/path/to/cargo"; exit 1; }

    # Build test binaries and list them. Only targets built as tests — the workspace's own
    # bins (probe, echo-server) appear in the same stream and are not test harnesses.
    local bins
    bins=$("$CARGO_BIN" test --workspace --offline --no-run --message-format=json 2>/dev/null \
        | python3 -c "import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line.startswith('{'):
        continue
    m = json.loads(line)
    if m.get('executable') and m.get('profile', {}).get('test'):
        print(m['executable'])")
    [ -n "$bins" ] || { echo "no test binaries built (cargo test --no-run failed?)"; exit 1; }

    trap 'ip netns del "$NS" 2>/dev/null' EXIT
    ip netns del "$NS" 2>/dev/null
    ip netns add "$NS"
    ip netns exec "$NS" ip link set lo up

    local rc=0
    while read -r bin; do
        echo "--- $(basename "$bin")"
        ip netns exec "$NS" "$bin" "${ARGS[@]}" 2>&1 | tail -3
        [ "${PIPESTATUS[0]}" -eq 0 ] || rc=1
    done <<< "$bins"

    if [ "$rc" -eq 0 ]; then echo "netns test suite: OK"; else echo "netns test suite: FAILED"; fi
    exit "$rc"
}

main
