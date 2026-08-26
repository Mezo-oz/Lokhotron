# Provisioning the RU / non-RU pair (Phase 1)

This directory turns two fresh Linux boxes into the Phase 1 measurement pair: a **non-RU echo
server** (the far end of the delta) and an **RU sensor** (runs the probe battery, captures the
delta, classifies it). Everything here is provider-agnostic and idempotent. It does **not** rent
the boxes — that's the part only you can do (credentials, cost, provider choice, and, for the RU
box, legal exposure). Once you have two hosts and their IPs, provisioning is one command each.

Why the pair is worth it, stated precisely: the calibrated instrument makes **both** outcomes of
the live run publishable. A live `injected_rst_at_sni` is trustworthy because the rig proved the
classifier resolves injected faults. And a live `timeout_indistinct` is now a *finding* — "the
TSPU is uniform at this granularity" — not "our tool is blind," because calibration ruled out the
blindness. That two-sided honesty is what you're buying with the $10 and the risk.

---

## Decisions that are yours (before you create anything)

1. **Providers / locations.** Non-RU server: anywhere outside RU with a stable public IP
   (ex-RU/EU/US VPS is fine). RU sensor: a Russian-operator VPS. Note the DC-vs-consumer caveat
   (DESIGN Correction 3) — a DC VPS characterizes the **datacenter** path, not consumer; scope the
   claim accordingly and lean on the OONI-residential comparison for the gap read.
2. **Legal / risk check for the RU box.** Verify current Russian legal exposure for running a
   measurement sensor before you create it — this is in the "verify before hardening" list and it
   changes. A VPS under your own name is lower human-risk than a volunteer's device, but it is
   still your call to accept. Don't skip this step.
3. **A port.** One UDP+TCP port for the echo server (default `47017`). Open it in the host
   firewall **and** the provider security group.

The scripts don't decide any of these — you pass them in.

---

## Non-RU server

On a clone of this repo on the box:

```sh
git clone https://github.com/Mezo-oz/Lokhotron && cd Lokhotron
sudo deploy/server-setup.sh 0.0.0.0:47017
```

Installs cargo if needed, builds `echo-server` (release), installs it as `lokhotron-echo`, runs it
under systemd (`DynamicUser`, hardened), and best-effort opens the port. Verify:

```sh
systemctl status lokhotron-echo
ss -lunp | grep 47017     # UDP listener
```

## RU sensor

On a clone of this repo on the box:

```sh
git clone https://github.com/Mezo-oz/Lokhotron && cd Lokhotron
sudo deploy/sensor-setup.sh <non-ru-server-ip>:47017 600 8
#                            \_______server_______/  \__/ \_/
#                                                  interval count(datagrams)
```

Then **fill in the box's tags** (meaningless data until you do):

```sh
sudoedit /etc/lokhotron/sensor.env    # set ASN= and REGION=
sudo systemctl start lokhotron-sensor.service   # one run now
tail -f /var/log/lokhotron/battery.jsonl
```

Each line is one tagged verdict:

```json
{"ts":"2026-08-26T18:00:00Z","asn":12389,"region":"ru-nw","verdict":{"kind":"ok"}}
```

The timer runs the battery every `interval` seconds with ±120 s jitter. **Gentleness is a safety
parameter** — a tight, regular cadence of odd probes is itself flaggable. Keep the interval loose.

---

## What this deploys vs. what it doesn't

**Deploys:** the two roles, the periodic battery, local tagged store-and-forward logging, and the
full verdict pipeline the rig verified (reachability, silent-drop, throttle, injected-RST with
per-route TTL calibration).

**Does not (Phase 2+, deliberately):** no ingest/collector (logs stay local — ship them yourself
for now), no signed bundles, no server-side capture (the RU sensor does the capture/classification
this phase), no Reality/active-probe endpoint on the server, no k>=5 edge aggregation. The
transport enum is still the draft set — reconcile with amnezia-client's real transports before
Phase 2 (CONTRACT open questions).

## Operational notes

- **Name invariant.** These boxes are *yours* (infrastructure), not the client, so the Lokhotron
  name is fine here — but the invariant (лохотрон never on anything a user/adversary sees) means:
  don't reuse these hostnames/keys/endpoints in anything client-facing, and don't advertise a
  sensor's server as a client endpoint.
- **Dark endpoints stay out of this.** If/when you add canary endpoints (DESIGN), they are
  provisioned separately and never appear in any client bundle. Don't fold them in here.
- **Teardown.** `sudo systemctl disable --now lokhotron-echo` /
  `lokhotron-sensor.timer`, then remove the unit files and `/usr/local/bin/lokhotron-*`.
