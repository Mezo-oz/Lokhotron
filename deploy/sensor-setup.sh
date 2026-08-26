#!/usr/bin/env bash
# Provision an RU-side sensor: builds the probe, installs a periodic (jittered) battery run
# against the non-RU echo server, and appends tagged verdicts to a local JSONL (store-and-
# forward stub). Idempotent. Run as root from a clone of this repo on the box:
#   sudo deploy/sensor-setup.sh <server_ip:47017> [interval_sec] [count]
#
# READ deploy/DEPLOY.md FIRST — running a sensor carries operational/legal considerations,
# and the gentleness of the interval is a safety parameter, not a performance knob.
set -euo pipefail

SERVER="${1:?usage: sensor-setup.sh <server_ip:port> [interval_sec] [count]}"
INTERVAL="${2:-600}"      # default 10 min; keep it gentle
COUNT="${3:-8}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (installs a systemd timer + needs CAP_NET_RAW)"; exit 1; }

ensure_cargo() {
    command -v cargo >/dev/null 2>&1 && return
    if command -v dnf >/dev/null 2>&1; then dnf install -y cargo
    elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y cargo
    else echo "install cargo manually, then re-run"; exit 1; fi
}
ensure_cargo

( cd "$REPO_ROOT" && cargo build --release -p probe )
install -m0755 "$REPO_ROOT/target/release/probe" /usr/local/bin/lokhotron-probe
install -m0755 "$REPO_ROOT/deploy/run-battery.sh" /usr/local/bin/lokhotron-run-battery

mkdir -p /var/log/lokhotron /etc/lokhotron

# Seed the config only on first run; never clobber an operator's edits.
if [ ! -f /etc/lokhotron/sensor.env ]; then
    sed "s|__SERVER__|$SERVER|; s|__COUNT__|$COUNT|" \
        "$REPO_ROOT/deploy/lokhotron-sensor.env.example" > /etc/lokhotron/sensor.env
    echo "wrote /etc/lokhotron/sensor.env — FILL IN ASN and REGION before trusting the data."
else
    echo "kept existing /etc/lokhotron/sensor.env"
fi

install -m0644 "$REPO_ROOT/deploy/systemd/lokhotron-sensor.service" /etc/systemd/system/lokhotron-sensor.service
sed "s|__INTERVAL__|$INTERVAL|g" "$REPO_ROOT/deploy/systemd/lokhotron-sensor.timer" \
    > /etc/systemd/system/lokhotron-sensor.timer
systemctl daemon-reload
systemctl enable --now lokhotron-sensor.timer

echo "OK: sensor battery every ${INTERVAL}s -> /var/log/lokhotron/battery.jsonl"
echo "    one-shot now:  systemctl start lokhotron-sensor.service"
echo "    watch:         tail -f /var/log/lokhotron/battery.jsonl"
