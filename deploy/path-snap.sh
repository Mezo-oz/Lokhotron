#!/usr/bin/env bash
# One compact path snapshot per battery run, appended to /var/log/<prefix>/path.jsonl.
#
# Installed by sensor-setup.sh as /usr/local/bin/<prefix>-path-snap and fired by the sensor
# unit's ExecStopPost. Carries no project name: it lands on the RU sensor. See DEPLOY.md
# "The name invariant".
#
# Why this exists: on 2026-09-21/22 the battery logged 144 non-ok verdicts over 38 hours and
# then went clean again. Host health and BGP both came back innocent, but no path data had been
# stored at the anomaly timestamps, so a reroute could not be ruled out and the episode stayed
# unexplained. This closes that gap for the next one.
#
# Target comes from the battery's own SERVER, never a literal here: run-battery forbids
# probing anything we do not own, and this must inherit that guarantee rather than restate it.
set -uo pipefail

ENV_FILE=/etc/${LOK_PREFIX:-netmon}/sensor.env
LOG=/var/log/${LOK_PREFIX:-netmon}/path.jsonl

[ -r "$ENV_FILE" ] || exit 0
SERVER=$(sed -n 's/^SERVER=//p' "$ENV_FILE" | tail -1)
HOST=${SERVER%%:*}
[ -n "$HOST" ] || exit 0

TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
START=$(date +%s)
# -n no DNS, -q1 one probe per hop, -w2 two-second wait, -m15 enough headroom for a longer
# path without paying 2 s per star out to 30.
OUT=$(traceroute -n -q1 -w2 -m15 "$HOST" 2>/dev/null)
ELAPSED=$(( $(date +%s) - START ))

printf '%s' "$OUT" | awk -v ts="$TS" -v host="$HOST" -v el="$ELAPSED" '
  NR==1 { next }                                  # drop the "traceroute to ..." banner
  {
    hop=$1; ip=""; ms=""
    for (i=2; i<=NF; i++) {
      if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && ip=="") ip=$i
      else if ($i ~ /^[0-9.]+$/ && ip!="" && ms=="") ms=$i
    }
    if (ip != "") { n++; hops[n]=hop":"ip":"ms; last=ip; lasthop=hop }
    else stars++
  }
  END {
    printf "{\"ts\":\"%s\",\"target\":\"%s\",\"elapsed_s\":%d,\"responding\":%d,\"silent\":%d,",
           ts, host, el, n+0, stars+0
    printf "\"last_hop\":%d,\"last_ip\":\"%s\",\"path\":[", lasthop+0, last
    for (i=1; i<=n; i++) {
      split(hops[i], f, ":")
      printf "%s{\"h\":%d,\"ip\":\"%s\",\"ms\":%s}", (i>1?",":""), f[1], f[2], (f[3]==""?"null":f[3])
    }
    printf "]}\n"
  }' >> "$LOG"

# Self-cap instead of logrotate: logrotate is not installed here and adding a package to this
# box for a 50 KB/day file is footprint for nothing. ~200k lines is about four years at the
# battery's cadence.
LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)
if [ "$LINES" -gt 200000 ]; then
  tail -n 150000 "$LOG" > "$LOG.trim" && mv "$LOG.trim" "$LOG"
fi
