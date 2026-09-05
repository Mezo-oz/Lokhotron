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

   **Which RU provider you pick decides what you can measure — treat it as a measurement decision,
   not a procurement one.** The Phase 0 read (`phase0/FINDINGS-2026-08-27.md`) found block rates
   spreading **87-96 pp between RU hosting providers on the same test in the same month**: one
   provider sat near-clean across Tor/Psiphon/Telegram while consumer operators were 75-99% blocked.
   Renting on price alone is choosing your findings at random. So: **rent 2-3 RU VPSes at different
   providers** rather than one — still inside the ~$10/mo envelope, and a single box cannot be
   called representative. Re-run `python phase0/ooni_gap.py` first; the picture is month-specific
   and a provider that looks clean today may be filtered by the time you rent.

   **A screened shortlist already exists: [../phase0/PROVIDER-SHORTLIST.md](../phase0/PROVIDER-SHORTLIST.md)**
   (22 candidates, OFAC-screened and checked against OONI coverage on 2026-08-27). Headlines:
   **Aeza is OFAC-designated — do not transact**; 13 of the 22 have no OONI coverage at all, so
   most providers cannot be previewed; and the nine that can fall into four distinct path profiles.
   The suggested three, chosen to *span* those profiles rather than duplicate one: **MTW**
   (consumer-like), **Timeweb** (protocol-selective, best-characterised), **Beget** (near-clean
   control). Regenerate with `python phase0/provider_screen.py`.

   **After renting, check the assigned IP's actual ASN** and set `ASN=`/`REGION=` in
   `/etc/lokhotron/sensor.env` accordingly — a plan can land in a different ASN than the one the
   OONI data describes, which would silently mislabel every verdict the sensor produces.
2. **Legal / sanctions check for the RU box — [LEGAL-RU.md](LEGAL-RU.md).** Done as a research
   pass on 2026-08-27; read it before you create anything, and re-read it at rent time because the
   law moves several times a year. The short version: the sensing layer's Russian-law exposure is
   low *because* the battery only ever talks to a host we own (keep it that way — Art. 274.1 is
   where third-party probing would land), the real Russian exposure sits on the **publishing** side
   under the March 2024 ban on disseminating circumvention information, and the sharpest near-term
   risk is **American**: OFAC designated the Russian hoster Aeza Group in July 2025, transacting
   with an SDN is strict liability, and `phase0/asn_classes.json` will happily classify a
   sanctioned provider as a perfectly good vantage. **OFAC-screen the provider before you pay.**
   A VPS under your own name is lower human-risk than a volunteer's device, but it is still your
   call to accept. Don't skip this step, and don't rent under false details.
3. **A port.** One UDP+TCP port for the echo server (default `47017`). Open it in the host
   firewall **and** the provider security group.
4. **How you carry the shared secret to each sensor.** The server and every sensor hold the same
   64-hex `LOK_PROBE_KEY`; `server-setup.sh` generates one if you don't supply it. It is what makes
   an arrival provable — without it an on-path device can reflect the probe's own datagrams and the
   run reads `ok` on a path that delivered nothing (ECHO §2a) — and it is what keeps the echo
   server from being an **open UDP reflector on a public IP**, which is an abuse report and a
   provider null-route away from looking exactly like a censorship finding. Carry it over your
   existing admin channel; it never needs to travel the measured path.

The scripts don't decide any of these — you pass them in.

---

## Non-RU server

On a clone of this repo on the box:

```sh
git clone https://github.com/Mezo-oz/Lokhotron && cd Lokhotron
sudo deploy/server-setup.sh 0.0.0.0:47017
```

Installs cargo if needed, builds `echo-server` (release), installs it as `lokhotron-echo`, runs it
under systemd (`DynamicUser`, hardened), and best-effort opens the port. It also **generates the
shared secret** into `/etc/lokhotron/echo.env` (0600) and prints it once — that value goes to every
sensor. Supply your own instead with `sudo LOK_PROBE_KEY=<64 hex> deploy/server-setup.sh ...`;
re-running keeps the installed key rather than rotating it out from under live sensors. Verify:

```sh
systemctl status lokhotron-echo
ss -lunp | grep 47017     # UDP listener
```

## RU sensor

On a clone of this repo on the box:

```sh
git clone https://github.com/Mezo-oz/Lokhotron && cd Lokhotron
sudo LOK_PROBE_KEY=<the server's 64-hex key> \
    deploy/sensor-setup.sh <non-ru-server-ip>:47017 600 8
#                           \_______server_______/  \__/ \_/
#                                                 interval count(datagrams)
```

The script ends with a **pre-flight battery run and will not enable the timer unless it comes back
`ok`.** That gate exists because a mismatched key, a closed provider security group, and a genuine
total block are indistinguishable in the data — all three produce nothing coming back. Sorting them
out here costs a minute; sorting them out later means discovering that a week of rows reading
"blocked" was a typo. If the block *is* the finding, re-run with `LOK_FORCE_ENABLE=1`.

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

Two things to know about those lines before you read a week of them:

- **`{"kind":"not_evaluated","reason":…,"detail":…}` is not a finding.** It means the run wrapper
  found the *instrument* unfit before or during the run — binary gone, config unreadable or
  unkeyed, no `CAP_NET_RAW`, probe crashed or timed out, or the echo *host* answered "nothing
  listening" — and refused to write a verdict about the TSPU. Every other kind, `timeout_indistinct`
  included, means the probe ran and is describing the path. Exclude `not_evaluated` rows from every
  rate; count them separately as sensor health (`grep -c not_evaluated`, and the unit shows in
  `systemctl --failed`). A wall of them is a box problem, fix the box. Contract 0.2 (CONTRACT.md).
- **An optional `"stderr"` field** rides next to the verdict when the probe said anything on its
  operator channel — the echo-integrity line (which leg was mutated, reflected/unauthenticated
  counts, keyed vs open mode) or a warning. It is context for you, not part of the verdict.

The timer runs the battery every `interval` seconds with ±120 s jitter. **Gentleness is a safety
parameter** — a tight, regular cadence of odd probes is itself flaggable. Keep the interval loose.

---

## What this deploys vs. what it doesn't

**Deploys:** the two roles, the periodic battery, local tagged store-and-forward logging, and the
full verdict pipeline the rig verified (reachability, silent-drop, throttle, injected-RST with
per-route TTL calibration, in-flight payload mutation, and in-flight rewrites of the probe's own
header). Every capture the sensor runs is scoped to the probe's own 5-tuple, so the box's other
traffic — your SSH session included — can't leak into a verdict; the rig proves that with a
negative case, not just a unit test. Arrivals are keyed, so a device that swallows the traffic and
reflects the probe back cannot make the path read healthy; that too has a rig case.

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
- **Key hygiene.** `/etc/lokhotron/echo.env` and `/etc/lokhotron/sensor.env` are 0600 and hold the
  shared secret; `sensor.env` is sourced with `set -a` so the probe actually sees it. To rotate,
  change both ends together — a sensor left on the old key goes silent, and silence is the one
  signal this system cannot tell apart from censorship.
- **Teardown.** `sudo systemctl disable --now lokhotron-echo` /
  `lokhotron-sensor.timer`, then remove the unit files and `/usr/local/bin/lokhotron-*`.
