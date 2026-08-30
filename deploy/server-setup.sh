#!/usr/bin/env bash
# Provision the NON-RU reverse-measurement endpoint (the echo server — the far end of the
# delta). Idempotent: safe to re-run. Run as root from a clone of this repo on the box:
#   sudo deploy/server-setup.sh 0.0.0.0:47017
#
# The shared secret comes from LOK_PROBE_KEY (64 hex chars) and is generated if unset. It
# must match every sensor's, and it is what stops this endpoint being an open UDP reflector
# on a public IP — the server answers only datagrams that authenticate against it.
set -euo pipefail

LISTEN="${1:?usage: server-setup.sh <listen_ip:port>   e.g. 0.0.0.0:47017}"
PORT="${LISTEN##*:}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (installs a systemd service)"; exit 1; }

# --- shared secret ----------------------------------------------------------
# Keep an already-installed key rather than rotating it out from under live sensors.
if [ -f /etc/lokhotron/echo.env ] && [ -z "${LOK_PROBE_KEY:-}" ]; then
    # shellcheck disable=SC1091
    LOK_PROBE_KEY="$(sed -n 's/^LOK_PROBE_KEY=//p' /etc/lokhotron/echo.env)"
    echo "kept the existing key in /etc/lokhotron/echo.env"
fi
if [ -z "${LOK_PROBE_KEY:-}" ]; then
    LOK_PROBE_KEY="$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    GENERATED=1
fi
case "$LOK_PROBE_KEY" in
    [0-9a-fA-F]*) [ "${#LOK_PROBE_KEY}" -eq 64 ] || { echo "LOK_PROBE_KEY must be 64 hex chars"; exit 1; } ;;
    *) echo "LOK_PROBE_KEY must be 64 hex chars"; exit 1 ;;
esac
mkdir -p /etc/lokhotron
umask 077
printf 'LOK_PROBE_KEY=%s\n' "$LOK_PROBE_KEY" > /etc/lokhotron/echo.env
chmod 0600 /etc/lokhotron/echo.env

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
if [ -n "${GENERATED:-}" ]; then
    echo
    echo "Generated the shared secret. Every sensor needs this exact value:"
    echo "    LOK_PROBE_KEY=$LOK_PROBE_KEY"
    echo "A sensor with the wrong key gets NO echoes back, which is indistinguishable from a"
    echo "total block — so carry it across carefully and let sensor-setup.sh's pre-flight run."
fi
