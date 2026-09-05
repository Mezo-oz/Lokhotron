#!/usr/bin/env bash
# One battery run: check the instrument is alive, probe the server, stamp + tag the verdict,
# append to the local JSONL. Invoked by lokhotron-sensor.service (timer-driven). Tags are
# coarse {asn, region} only — no user identifier, no precise location (CONTRACT.md Part 2).
#
# Two kinds of row come out of here, and the whole point of this file is to never confuse them:
#
#   a MEASUREMENT  — the probe ran, its channel was sound, and the verdict (even the null one,
#                    `timeout_indistinct`) is a claim about the path;
#   `not_evaluated` — the instrument could not run or could not be trusted, so the row is a
#                    claim about THIS BOX and says nothing about the TSPU.
#
# Before contract 0.2 every failure here — missing binary, unreadable config, no CAP_NET_RAW, a
# probe that crashed — was recorded as `timeout_indistinct`, i.e. as censorship. sensor-setup.sh
# gates once at install; this gate runs on every tick, because a box gets suspended, a port gets
# null-routed and a config gets fat-fingered *after* install. dpi-bench got burned by exactly
# this shape (a rig that was never up read as 29 findings) and grew an `exit 2` state for it;
# `not_evaluated` is that state pulled across the boundary.
#
# What this gate deliberately does NOT try to decide: whether the echo server is up. From the
# RU side a dead server, a wrong key and a total block are the same silence, and the only host
# we are allowed to probe is our own. A silence that is really a server outage is caught at
# analysis by (a) the server's own journal and (b) all sensors going silent at the same instant.
# Don't add a "ping something else" check here — third-party probing is the legal line.
set -uo pipefail   # no -e: every failure below is handled, and every run writes exactly one row

# Overridable so the gate itself can be tested (rig/, or by hand) without touching /etc or /var.
LOG="${LOK_BATTERY_LOG:-/var/log/lokhotron/battery.jsonl}"
ENV_FILE="${LOK_SENSOR_ENV:-/etc/lokhotron/sensor.env}"
PROBE="${LOK_PROBE_BIN:-/usr/local/bin/lokhotron-probe}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-120}"   # seconds; well above the probe's own socket timeouts

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Make an arbitrary string safe inside a JSON string literal: cap the length, fold newlines/
# tabs to spaces, drop the remaining control bytes, then escape backslash and quote. `detail`
# is an operator diagnostic, nothing aggregates on it, so lossy is fine — unparseable is not.
# The cap is applied to the INPUT, before escaping: truncating afterwards can split an escape
# pair and leave a trailing lone backslash, which escapes the closing quote and makes the whole
# row unparseable — the one outcome worse than the timeout_indistinct this file exists to stop.
json_str() {
    printf '%s' "${1:0:400}" | tr '\n\r\t' '   ' | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# Append one row. $1 = verdict JSON, $2 = optional extra fields (already JSON, leading comma).
emit() {
    local asn="${ASN:-0}" region="${REGION:-unknown}"
    [[ "$asn" =~ ^[0-9]+$ ]] || asn=0     # ASN is a JSON number; never let a stray value break the log
    printf '{"ts":"%s","asn":%s,"region":"%s","verdict":%s%s}\n' \
        "$ts" "$asn" "$(json_str "$region")" "$1" "${2:-}" >> "$LOG"
}

# Record that no measurement was made, say so on stderr (the journal), and exit non-zero so the
# unit shows in `systemctl --failed`. The timer still fires next tick — a failed oneshot does
# not stop its timer — so the box keeps trying, visibly, rather than silently or falsely.
not_evaluated() {
    local reason="$1" detail="$2"
    emit "$(printf '{"kind":"not_evaluated","reason":"%s","detail":"%s"}' "$reason" "$(json_str "$detail")")"
    echo "not_evaluated ($reason): $detail" >&2
    exit 1
}

mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

# --- liveness preconditions (about this box, checked every run) -------------------------------

# 1. Config readable and complete. Sourced with `set -a` so LOK_PROBE_KEY reaches the probe as an
#    environment variable — sourcing alone makes a shell variable, and the probe would silently
#    fall back to open mode, where an echo proves nothing.
[ -r "$ENV_FILE" ] || not_evaluated config_invalid "$ENV_FILE unreadable or missing"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE" || not_evaluated config_invalid "$ENV_FILE failed to source"
set +a
[ -n "${SERVER:-}" ] || not_evaluated config_invalid "SERVER not set in $ENV_FILE"
[[ "${LOK_PROBE_KEY:-}" =~ ^[0-9a-fA-F]{64}$ ]] \
    || not_evaluated config_invalid "LOK_PROBE_KEY missing or not 64 hex in $ENV_FILE (an unkeyed run cannot prove delivery)"

# 2. Probe present.
[ -x "$PROBE" ] || not_evaluated probe_missing "$PROBE missing or not executable"

# 3. CAP_NET_RAW in our effective set (bit 13 of CapEff). Without it the probe still runs — it
#    degrades to a plain TCP probe — but then it can't see an injected RST, and every RST-based
#    block would land in timeout_indistinct as a false null. Degraded is not "a bit worse" here;
#    it moves rows between columns, so it is not a measurement.
capeff="$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null || true)"
[ -n "$capeff" ] || not_evaluated no_capability "could not read CapEff from /proc/self/status"
if (( ((16#$capeff >> 13) & 1) == 0 )); then
    not_evaluated no_capability "CapEff=$capeff lacks CAP_NET_RAW (bit 13); run via the unit or as root"
fi

# --- the run ------------------------------------------------------------------------------------

# stdout is the verdict; stderr is the operator channel (open-mode warning, echo-integrity line
# with the mutation leg, errors). Keep them apart: the old `2>/dev/null` threw away the only
# evidence of *which* failure happened.
errf="$(mktemp)"
trap 'rm -f "$errf"' EXIT

if command -v timeout >/dev/null 2>&1; then
    out="$(timeout --kill-after=10 "$PROBE_TIMEOUT" "$PROBE" "$SERVER" "${COUNT:-8}" 2>"$errf")"
else
    out="$("$PROBE" "$SERVER" "${COUNT:-8}" 2>"$errf")"
fi
rc=$?
err="$(cat "$errf")"

# Non-zero exit is the probe saying it could not *run* — not that the path was bad. Its recv
# loop treats silence as an Observation (a drop becomes a measurement, correctly), so Err only
# comes from a local socket failure or from the far HOST answering "nothing listens here"
# (ICMP port unreachable -> ECONNREFUSED on the connected UDP socket). That second one is the
# single server-down signal an RU sensor can actually see; it lands here as probe_error with
# "Connection refused" in the detail. A middlebox could forge that ICMP, which would also land
# here — visibly, with the errno, where an operator can judge it, not in the censorship column.
case "$rc" in
    0)   ;;
    124|137) not_evaluated probe_error "probe exceeded ${PROBE_TIMEOUT}s and was killed; stderr: $err" ;;
    *)   not_evaluated probe_error "probe exit $rc; stderr: $err" ;;
esac

# The probe prints exactly one JSON object whose first key is "kind". Anything else — a panic
# message on stdout, an empty line, a newer probe speaking a shape this wrapper doesn't know —
# is a malformed row, not a null verdict.
[[ "$out" =~ ^\{\"kind\":\"[a-z_]+\" ]] \
    || not_evaluated malformed_verdict "unexpected probe output: ${out:-<empty>}; stderr: $err"

# A measurement. Carry the probe's stderr alongside (never inside) the verdict when there is
# any: today that is where the echo-integrity detail — which leg was mutated, reflected /
# unauthenticated counts, keyed or open mode — lives until the collector gives it a home.
extra=""
[ -n "$err" ] && extra=",\"stderr\":\"$(json_str "$err")\""
emit "$out" "$extra"
