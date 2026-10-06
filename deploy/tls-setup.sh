#!/usr/bin/env bash
# Provision the TLS listener the RIPE Atlas sslcert run targets (phase0/atlas_residential.py),
# on the SAME box as the echo server. Optional: only the Atlas baseline needs it. Idempotent.
# Run as root from a clone of this repo on the box:
#   sudo deploy/tls-setup.sh <public_ipv4> [port]          port defaults to 443
#
# The cert is self-signed for the box's IP. Its SHA-256 fingerprint is the ground truth every
# Atlas sslcert result is diffed against, so an existing cert is KEPT: regenerating it would
# silently invalidate the recorded fingerprint. Delete it by hand if you mean to rotate it.
set -euo pipefail

IP="${1:?usage: tls-setup.sh <public_ipv4> [port]}"
PORT="${2:-443}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (binds a privileged port, installs a systemd service)"; exit 1; }
[[ "$IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "expected an IPv4 address, got '$IP'"; exit 1; }

# Same namespace as server-setup.sh, so the pair reads as one deployment.
LOK_PREFIX="${LOK_PREFIX:-netmon}"
[[ "$LOK_PREFIX" =~ ^[a-z][a-z0-9-]{1,30}$ ]] \
    || { echo "LOK_PREFIX must match ^[a-z][a-z0-9-]{1,30}$ (got '$LOK_PREFIX')"; exit 1; }
ETC="/etc/$LOK_PREFIX-tls"
OPT="/opt/$LOK_PREFIX-tls"

command -v python3 >/dev/null && command -v openssl >/dev/null \
    || { echo "needs python3 and openssl"; exit 1; }

# --- cert -------------------------------------------------------------------
mkdir -p "$ETC"
if [ -f "$ETC/cert.pem" ] && [ -f "$ETC/key.pem" ]; then
    echo "kept the existing cert in $ETC"
else
    ( umask 077
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
          -keyout "$ETC/key.pem" -out "$ETC/cert.pem" -days 365 \
          -subj "/CN=$IP" -addext "subjectAltName=IP:$IP" )
    chmod 0644 "$ETC/cert.pem"; chmod 0600 "$ETC/key.pem"
    GENERATED=1
fi

# --- responder + unit -------------------------------------------------------
install -d -m0755 "$OPT"
install -m0644 "$REPO_ROOT/deploy/tls-responder.py" "$OPT/server.py"
sed "s|__PREFIX__|$LOK_PREFIX|g; s|__PORT__|$PORT|g" "$REPO_ROOT/deploy/systemd/lokhotron-tls.service" \
    > "/etc/systemd/system/$LOK_PREFIX-tls.service"
chmod 0644 "/etc/systemd/system/$LOK_PREFIX-tls.service"
systemctl daemon-reload
systemctl enable "$LOK_PREFIX-tls.service"
systemctl restart "$LOK_PREFIX-tls.service"   # restart, not --now: a re-run must pick up a new script

# --- firewall (best-effort; the provider security group still matters) ------
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port="$PORT/tcp" && firewall-cmd --reload
elif command -v ufw >/dev/null 2>&1; then
    ufw allow "$PORT/tcp"
else
    echo "NOTE: open $PORT/tcp in the host firewall AND the provider's security group."
fi

# --- check it actually answers ---------------------------------------------
# systemd "active" proved nothing last time; a completed handshake does.
sleep 1
FP="$(echo | timeout 10 openssl s_client -connect "127.0.0.1:$PORT" 2>/dev/null \
      | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
[ -n "$FP" ] || { echo "FAIL: no TLS handshake on 127.0.0.1:$PORT — see journalctl -u $LOK_PREFIX-tls"; exit 1; }
echo "OK: $LOK_PREFIX-tls answering on $PORT/tcp."
echo "    $FP"
if [ -n "${GENERATED:-}" ]; then
    echo "New cert. Record that fingerprint privately: every sslcert result is diffed against it."
else
    echo "Existing cert kept. That fingerprint should match the one you recorded."
fi
