#!/usr/bin/env bash
# Provision the NON-RU reverse-measurement endpoint (the echo server — the far end of the
# delta). Idempotent: safe to re-run. Run as root from a clone of this repo on the box:
#   sudo deploy/server-setup.sh 0.0.0.0:47017
set -euo pipefail

LISTEN="${1:?usage: server-setup.sh <listen_ip:port>   e.g. 0.0.0.0:47017}"
PORT="${LISTEN##*:}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (installs a systemd service)"; exit 1; }

# --- deps: a Rust toolchain -------------------------------------------------
ensure_cargo() {
    command -v cargo >/dev/null 2>&1 && return
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y cargo
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y cargo
    else
        echo "install a Rust toolchain (cargo) manually, then re-run"; exit 1
    fi
}
ensure_cargo

# --- build + install --------------------------------------------------------
( cd "$REPO_ROOT" && cargo build --release -p echo-server )
install -m0755 "$REPO_ROOT/target/release/echo-server" /usr/local/bin/lokhotron-echo

# --- systemd service --------------------------------------------------------
sed "s|__LISTEN__|$LISTEN|g" "$REPO_ROOT/deploy/systemd/lokhotron-echo.service" \
    > /etc/systemd/system/lokhotron-echo.service
systemctl daemon-reload
systemctl enable --now lokhotron-echo.service

# --- firewall (best-effort; the provider security group still matters) ------
open_port() {
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="$PORT/udp" --add-port="$PORT/tcp" && firewall-cmd --reload
    elif command -v ufw >/dev/null 2>&1; then
        ufw allow "$PORT/udp"; ufw allow "$PORT/tcp"
    else
        echo "NOTE: open $PORT (udp+tcp) in the host firewall AND the provider's security group."
    fi
}
open_port

echo "OK: lokhotron-echo listening on $LISTEN (udp+tcp). Status: systemctl status lokhotron-echo"
