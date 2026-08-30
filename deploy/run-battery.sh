#!/usr/bin/env bash
# One battery run: probe the server, stamp + tag the verdict, append to the local JSONL.
# Invoked by lokhotron-sensor.service (timer-driven). Tags are coarse {asn, region} only —
# no user identifier, no precise location (see CONTRACT.md Part 2 / the k-anon rules).
set -euo pipefail

# `set -a` so LOK_PROBE_KEY reaches the probe as an environment variable: sourcing alone
# makes it a shell variable, and the probe would silently fall back to open mode.
set -a
# shellcheck disable=SC1091
source /etc/lokhotron/sensor.env
set +a

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# On any failure, record the honest null rather than dropping the sample.
verdict="$(/usr/local/bin/lokhotron-probe "$SERVER" "${COUNT:-8}" 2>/dev/null || echo '{"kind":"timeout_indistinct"}')"

printf '{"ts":"%s","asn":%s,"region":"%s","verdict":%s}\n' \
    "$ts" "${ASN:-0}" "${REGION:-unknown}" "$verdict" \
    >> /var/log/lokhotron/battery.jsonl
