#!/usr/bin/env bash
# Provision an RU-side sensor: builds the probe, installs a periodic (jittered) battery run
# against the non-RU echo server, and appends tagged verdicts to a local JSONL (store-and-
# forward stub). Idempotent. Run as root from a clone of this repo on the box:
#   sudo LOK_PROBE_KEY=<64 hex> deploy/sensor-setup.sh <server_ip:47017> [interval_sec] [count]
#
# Nothing this installs carries the project name. Every path, binary and unit is namespaced by
# LOK_PREFIX (default `netmon`) because the sensor is RU-facing: a box that names the project
# ties itself to the public repo, and the repo is the publishing layer that carries the actual
# legal exposure. The tooling enforces it so it cannot be forgotten — see DEPLOY.md.
#
# LOK_PROBE_KEY must be the exact secret the echo server was provisioned with. A wrong key
# means the server answers nothing, and every verdict this sensor ever produces reads as a
# total block — so the script ends with a pre-flight run and refuses to enable the timer if
# that run is not `ok` (override with LOK_FORCE_ENABLE=1 once you have ruled out the key).
#
# READ deploy/DEPLOY.md FIRST — running a sensor carries operational/legal considerations,
# and the gentleness of the interval is a safety parameter, not a performance knob.
set -euo pipefail

SERVER="${1:?usage: sensor-setup.sh <server_ip:port> [interval_sec] [count]}"
INTERVAL="${2:-600}"      # default 10 min; keep it gentle
COUNT="${3:-8}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY="${LOK_PROBE_KEY:?set LOK_PROBE_KEY to the 64-hex secret the echo server runs with}"
[ "${#KEY}" -eq 64 ] || { echo "LOK_PROBE_KEY must be 64 hex chars"; exit 1; }

[ "$(id -u)" -eq 0 ] || { echo "run as root (installs a systemd timer + needs CAP_NET_RAW)"; exit 1; }

# Namespace for everything that lands on disk. Validated because it is interpolated into paths
# and unit names: a stray value here writes files somewhere unintended.
LOK_PREFIX="${LOK_PREFIX:-netmon}"
[[ "$LOK_PREFIX" =~ ^[a-z][a-z0-9-]{1,30}$ ]] \
    || { echo "LOK_PREFIX must match ^[a-z][a-z0-9-]{1,30}$ (got '$LOK_PREFIX')"; exit 1; }
case "$LOK_PREFIX" in *lokhotron*|*lohotron*)
    echo "LOK_PREFIX must not name the project"; exit 1 ;; esac

ensure_cargo() {
    command -v cargo >/dev/null 2>&1 && return
    if command -v dnf >/dev/null 2>&1; then dnf install -y cargo
    elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y cargo
    else echo "install cargo manually, then re-run"; exit 1; fi
}
ensure_cargo

( cd "$REPO_ROOT" && cargo build --release -p probe )
install -m0755 "$REPO_ROOT/target/release/probe" "/usr/local/bin/$LOK_PREFIX-probe"
install -m0755 "$REPO_ROOT/deploy/run-battery.sh" "/usr/local/bin/$LOK_PREFIX-run-battery"

mkdir -p "/var/log/$LOK_PREFIX" "/etc/$LOK_PREFIX"

# Seed the config only on first run; never clobber an operator's edits.
if [ ! -f "/etc/$LOK_PREFIX/sensor.env" ]; then
    umask 077
    sed "s|__SERVER__|$SERVER|; s|__COUNT__|$COUNT|; s|__KEY__|$KEY|; s|__PREFIX__|$LOK_PREFIX|g" \
        "$REPO_ROOT/deploy/lokhotron-sensor.env.example" > "/etc/$LOK_PREFIX/sensor.env"
    chmod 0600 "/etc/$LOK_PREFIX/sensor.env"
    echo "wrote /etc/$LOK_PREFIX/sensor.env — FILL IN ASN and REGION before trusting the data."
else
    echo "kept existing /etc/$LOK_PREFIX/sensor.env (edit LOK_PROBE_KEY there to rotate)"
fi

sed "s|__PREFIX__|$LOK_PREFIX|g" "$REPO_ROOT/deploy/systemd/lokhotron-sensor.service" \
    > "/etc/systemd/system/$LOK_PREFIX-sensor.service"
chmod 0644 "/etc/systemd/system/$LOK_PREFIX-sensor.service"
sed "s|__INTERVAL__|$INTERVAL|g; s|__PREFIX__|$LOK_PREFIX|g" "$REPO_ROOT/deploy/systemd/lokhotron-sensor.timer" \
    > "/etc/systemd/system/$LOK_PREFIX-sensor.timer"
chmod 0644 "/etc/systemd/system/$LOK_PREFIX-sensor.timer"
systemctl daemon-reload

# --- pre-flight -------------------------------------------------------------
# A wrong key, a closed provider security group, and a real total block all look identical
# in the data: nothing comes back. Distinguish them here, once, while you still have the
# context to fix the first two — rather than three days into a run whose every row says
# "blocked". This is the one check that needs a human: the per-run gate in run-battery.sh
# catches everything the box can know about itself (binary, config, CAP_NET_RAW, probe
# crash) and records it as `not_evaluated`, but "wrong key vs. real block" is silence either
# way and only you, right now, can tell which.
echo "pre-flight: one battery run against $SERVER ..."
preflight="$(LOK_PROBE_KEY="$KEY" "/usr/local/bin/$LOK_PREFIX-probe" "$SERVER" "$COUNT" 2>&1 || true)"
echo "  -> $preflight"
if grep -q '"kind":"ok"' <<< "$preflight"; then
    systemctl enable --now "$LOK_PREFIX-sensor.timer"
    echo "OK: sensor battery every ${INTERVAL}s -> /var/log/$LOK_PREFIX/battery.jsonl"
    echo "    one-shot now:  systemctl start $LOK_PREFIX-sensor.service"
    echo "    watch:         tail -f /var/log/$LOK_PREFIX/battery.jsonl"
    echo "    health:        grep -c '\"kind\":\"not_evaluated\"' /var/log/$LOK_PREFIX/battery.jsonl"
    echo "                   (instrument failures — never censorship; also: systemctl --failed)"
elif [ -n "${LOK_FORCE_ENABLE:-}" ]; then
    systemctl enable --now "$LOK_PREFIX-sensor.timer"
    echo "WARNING: pre-flight was not ok; enabled anyway because LOK_FORCE_ENABLE is set."
else
    echo
    echo "TIMER NOT ENABLED. The pre-flight did not come back ok, which is either a real"
    echo "finding or one of three configuration mistakes that look exactly like one:"
    echo "  1. the key here does not match the echo server's (/etc/<prefix>/echo.env there)"
    echo "  2. port ${SERVER##*:} is closed in the provider security group or host firewall"
    echo "  3. the echo server is not running (systemctl status <prefix>-echo)"
    echo "Rule those out and re-run, or set LOK_FORCE_ENABLE=1 if the block is the finding."
    exit 1
fi

# The working tree is the largest name leak on a sensor and the one the prefix cannot reach: a
# clone carries STATUS.md, LEGAL-RU.md and writeups/ onto the box. Say so while the operator is
# still at the prompt.
echo
echo "LAST STEP — remove this clone. Nothing under /usr/local, /etc or /var names the project,"
echo "but this working tree does:"
echo "    cd / && rm -rf '$REPO_ROOT'"
