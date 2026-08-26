# Lokhotron — design

Sensing layer (tree #1 of the system). Runs on **your infrastructure** — Linux VPSes outside
and inside Russia. Continuously learns **what the TSPU is doing right now, per operator and
region**, and turns that into signed "use this transport here" intelligence that clients inside
Russia consume to heal themselves. The brain runs from the US; sensors live in Russia; clients
(tree #2) are beneficiaries and, eventually, sensors.

This repo is **not** the client. See the boundary section — that separation is a security
control, not tidiness.

---

## The three trees, and why they're separate

The whole system is three cleanly separated trees, split by **deployment target and trust
boundary**:

1. **`dpi-bench`** — the offline zapret2 strategy harness. Teaches the capture/diff primitive
   on a lab target. Already exists (`X:\DPI-Tester`).
2. **Lokhotron (this repo)** — the sensing layer. Your infrastructure: probe, reverse-measurement
   server, collector, control plane. Build this now.
3. **The client (#2)** — ships to phones. **Its own repo, or (more likely) contributed work
   against amnezia-client upstream.** Built later, once Lokhotron's findings justify it.

### Why #1 and #2 are separate repos — least disclosure at the source level

The same principle as the per-region bundle slices, applied to source code. **The client ships
to adversary-controlled phones.** RKN installs it and reverse-engineers it. So the client's
source must not contain what the sensing layer knows: the full endpoint inventory, the
dark-canary identities, the control-plane decision logic, other regions' data, the
measurement-server internals. If #1 and #2 were one repo, all of that sits in a tree that's
handed over the moment the app is unpacked.

Splitting the repos enforces at the source level exactly what the per-region bundle slices
enforce at runtime: **the client only ever contains what a client is allowed to know. You can't
leak a canary list that isn't in the repo.**

Ordinary engineering reasons stack on the same conclusion:

- **Different toolchains.** #1 is Rust + Python + SQL on Linux. #2 is Kotlin / Gradle / Android
  NDK on a handset. A monorepo welds two unrelated build systems for no benefit.
- **Different cadence and trust.** Lokhotron's probe pair is fast-moving and publishable
  (net4people). The client is a slow, audited, high-trust artifact. Coupling releases couples
  trust.
- **Arm's length already.** The only thing crossing the boundary is a **contract, not code** —
  the signed strategy-bundle format going out, the telemetry schema coming in, the verdict
  vocabulary shared. That's a versioned spec ([CONTRACT.md](CONTRACT.md)), not a shared library.
  Same relationship as zapret ↔ dpi-bench.

### Lokhotron is one repo, not several

Inside this tree the probe, reverse-measurement server, collector, and control plane are all
"your infrastructure," same language family, deployed together — so they live as multiple
crates/packages in **one workspace**. Don't over-split within #1.

### The client is probably Amnezia upstream, not a repo you own

An unknown American VPN is exactly what a careful Russian shouldn't install. The credible path
for #2 is contributing to **amnezia-client** (fork/branch/PRs), inheriting its trust anchor and
its existing config-update channel rather than starting from zero. In that case #2 isn't "your
repo #2" — it's upstream work against Amnezia, which makes it **more** separate from Lokhotron,
not less. Its design notes live outside this repo (`X:\Lokhotron-client\DISTRIBUTION.md`) and
must not be pulled in here.

**Platform:** Android-first and, for the sensor mesh, Android-only — that's what the userbase
runs, the only platform with grassroots sideloading and offline replication, and the only place
client-as-sensor can scale. iOS, if ever supported, is a store-delivered bundle consumer only,
never a sensor or re-distributor.

---

## The two core insights (kept, but narrowed)

**#1 — You measure the delta, not the box.** You can't see the TSPU; you can see *what it did*
by diffing what a sensor sent against what a server you control received. The *shape* of the
difference is a diagnosis, not pass/fail.

**#2 — Your users are your sensor network.** Every client is already trying transports and
observing outcomes. With consent and anonymization, the userbase becomes the sensor mesh —
OONI fused into the product, self-reinforcing, zero marginal cost per sensor.

Both survive scrutiny. The corrections below are about *how much* carries over from dpi-bench,
*which* diagnoses actually need the byte-diff, and three failure modes the original concept
underweighted.

---

## Correction 1: the control plane is a targeting oracle (the biggest hole)

The concept doc worried about the signed bundle being **poisoned**. The worse problem is it
being **read**. RKN installs the client, watches the bundle, and learns — at your own
minutes-of-latency SLA — exactly which transport currently survives in which ASN. Signing stops
forgery; it does nothing about disclosure. A naive design is a machine that tells the censor
where to aim, continuously, for free.

Two consequences designed in, not bolted on:

- **"Heals faster than the censor iterates" is a bet, not a fact.** Your push channel makes
  their iteration cheap. State it as a wager and say why your strategy space is deeper than
  their patch rate — that's the thesis, so defend it explicitly.
- **Argmax builds a monoculture.** "Pick the current best transport per region" converges the
  fleet onto one channel — the most observable configuration possible, ideal for RKN to *not*
  block and instead monitor. **Fix:** the bundle carries a **distribution over surviving
  transports** with weights; each client samples ([CONTRACT.md](CONTRACT.md)). Same healing, no
  fleet-wide tell, and a Potemkin path can't capture everyone. Diversity is a security property.

**Dark endpoints (cheap, day one).** Keep measurement endpoints that **never appear in any
bundle**, used only for ground truth. The only real detector for "RKN gave my advertised servers
a clean path while blocking real users" — a bias applied to 100% of a channel is invisible to
outlier rejection but visible against a dark control.

---

## Correction 2: what actually carries over from dpi-bench is narrow

The concept doc claimed "the diff logic and even some of the reassembly/inspection code can
carry over." The reassembler specifically **does not** — dpi-bench's own DESIGN already made this
correction for IceSickle: *"What actually transfers is the narrow thing: capture the emitted
artifact, then assert properties on it."*

The reassembler's whole purpose is to **substitute for an endpoint that isn't there**
(below-window discard, first-writer-wins, `OverlapPolicy`). On the live wire your measurement
server **is** a real endpoint — the kernel does that for free. What you need is raw capture below
the stack (AF_PACKET / pcap), which is different code.

What **does** transfer: the discipline (capture the artifact, assert properties on it); the pcap
/ `etherparse` plumbing and `sendto`-interposer-style capture know-how; and most valuable, the
**property-vocabulary method**. dpi-bench works because it defined a closed set of assertions up
front. The live analogue is the **verdict vocabulary** — defined in [CONTRACT.md](CONTRACT.md),
before collecting anything.

### Which diagnoses actually need the byte-diff

| Diagnosis | Where observable | Needs byte-diff? |
|---|---|---|
| RST-after-SNI | client-side (RST TTL/IP-ID self-identifies) | no |
| Throughput collapse / throttle | client-side | no |
| UDP-dies-TCP-lives | client-side | no |
| Reality-probe-forwarded | **server-side logs only** | no (logs, not diff) |

The byte-level diff earns its keep on a **narrower** set: **selective drop** (which segment went
silent) and **payload mutation** (was anything rewritten). Real and worth building, but **not**
the load-bearing insight. Its MVP is a **sequence-marked echo protocol** — sensor sends numbered
segments, server reports the highest marker it saw and the TTL of any RST — not a full diff
engine.

---

## Correction 3: the DC/consumer gap is the central constraint, not a caveat

TSPU is deployed **at the operator.** Russian datacenter ASNs may sit behind a *different* box,
or none. A cheap RU VPS sensor isn't a lenient measurement of the same device — it may be
measuring **a different device, or no device.** Not "coarse coverage" — potentially
**categorically wrong** coverage.

Consequence that reshapes the roadmap: **the measurement you most need (residential) is the one
you're least able to ethically obtain.** That makes **client-as-sensor the unlock, not the
capstone** — the only path to residential signal at scale without risking named volunteers. So:

- The telemetry schema and consent flow **constrain everything upstream** — spec them day one
  even though they ship last ([CONTRACT.md](CONTRACT.md)). Retrofitting k-anonymity onto a
  collector built for rich probe data is how you build a database you can't defend.
- **Aggregate at the edge; don't collect-then-strip.** The collector must be unable to
  reconstruct who reported what **even under coercion of the collector** — you're US-operated,
  compelled disclosure is a real threat, cheaper to design out than to litigate.
- k-anonymity to {ASN, region}, no user identifier, or **drop the report.**

---

## Phasing (Phase 0 and Phase 1 inverted from the concept doc)

Phase 0 as a leading OONI/Censored-Planet dashboard is a map of **web** censorship — a different
territory, weakly correlated with the **VPN-protocol shaping** the client cares about (Censored
Planet can't see the latter). Risk: three weeks of beautiful dashboard driving zero client
decisions.

Phase 1's minimum form is **one RU VPS + one non-RU VPS + a probe battery** — a weekend and
~$10/mo. That's the scarce asset and the thesis test. If the delta is uninformative (everything
times out identically, no distinguishable shapes), you want that in week one.

- **Phase 0 (≤1 week, time-boxed):** ingest OONI + Censored Planet + GFW Report / net4people as
  **context for interpreting your own probes**, not the headline. Only write ingest code Phase 1
  reuses.
- **Phase 1 (the you-shaped core, a complete deliverable):** one non-RU reverse-measurement
  server + a couple RU VPS + maybe 1–2 vetted residential volunteers. Run the probe battery. Get
  the **sequence-marked echo delta** working. A differential probe pair that outputs *"here's what
  the TSPU did to an AmneziaWG handshake in Rostelecom today, at segment granularity"* is
  **publishable on its own** (net4people) and earns the credibility that makes volunteer
  recruitment and client adoption plausible later.
- **Phase 2:** analysis layer (survival **distribution** per {ASN, region}, not argmax) + signed
  strategy-bundle push with sampling + dark endpoints.
- **Phase 3:** fuse with the client — opt-in client-as-sensor telemetry (the residential unlock)
  feeding the store, clients auto-healing from bundles. **Everything downstream is justified by
  what Phase 1 finds, not committed now.**

---

## Architecture (six pieces, corrected)

```
  [ Android sensors in RU ] --gentle probes--> [ reverse-measurement servers (non-RU) ]
        |     (+ dark endpoints, never advertised)          |
        |  k-anon outcome reports, aggregated at edge       |  logs what actually arrived
        v                                                   v
  [ censorship-resistant ingest ] --------------------> [ collector + time-series store ]
     (store-and-forward; buffer when blocked)               |
                                                            v
                              [ analysis: survival DISTRIBUTION per {ASN,region,transport} ]
                                                            |
                                                            v
                        [ SIGNED bundles = weighted transport mix ] --push--> [ clients sample ]
                                     ^                                              |
                                     |______ opt-in client outcomes reported back _|
```

1. **Sensors (Android, in RU).** Probe battery: AmneziaWG, VLESS+Reality, Shadowsocks-2022,
   obfs4, plain-TLS control → known endpoints. Record verdict-vocabulary outcome + metrics, tag
   {ASN, region, timestamp}. **Gentle** — spread out, low-rate, cover-consistent, opt-in (a
   20-connection burst to odd endpoints is itself flaggable in 2026).
2. **Reverse-measurement servers (non-RU).** The other end of the delta. Raw capture below the
   stack; log bytes/timing/resets. Plus **dark endpoints** never named in any bundle.
3. **Censorship-resistant ingest.** Reporting out is itself censored traffic. Domain-fronting /
   ride the tunnel while up / DNS-TXT / **store-and-forward**. Accept going partially blind
   during total shutdowns — the *return* of reports after a blackout is itself signal.
4. **Collector + store.** Time-series keyed {operator, region, transport, endpoint, time}.
   Postgres/SQLite first; ClickHouse only when volume demands. **Aggregate at the edge.**
5. **Analysis / decision.** Rules first: survival **distribution** over last N minutes per {ASN,
   region}. Anomaly detection later. **Never argmax to a single transport.**
6. **Signed push.** Weighted transport mix, signed, clients verify. Same resistant-distribution +
   key-pinning problem as the client binary and the bootstrap — solve the key problem **once**.

---

## Smaller decisions on the record

- **Clock correlation.** Don't trust absolute in-country clocks — correlate sensor/server events
  by 5-tuple + a nonce carried in the payload.
- **Reuse the bootstrap you have.** The signed-bundle channel is the same problem amnezia-client
  already solves for config updates. Check whether the existing update path can carry bundles
  before building a seventh subsystem.
- **Adversary poisoning.** Fake sensors feeding "everything works," or fingerprinting your
  servers for a Potemkin path. Mitigation: many independent sensors, outlier rejection, **dark
  endpoints**, trust real-user telemetry over probes (harder to fake at scale).
- **The measurement can endanger the measurer.** Study OONI's risk methodology before recruiting
  a human sensor. A VPS under your own name carries far less human risk than a volunteer's phone.
  k-anon or drop.

---

## The founding principle (applies here too, via Phase 3)

Lokhotron's Phase 3 makes the client a sensor, so the client-side ethic binds this project:

> **The client never runs on anyone who did not install it. Deniability is a capability given to
> an informed user, never a state of ignorance imposed on them.**

Full rationale and the Android duress/PanicKit design in `X:\Lokhotron-client\DISTRIBUTION.md`
(tree #2 — not part of this repo).

---

## To verify before this hardens (don't trust from memory)

- TSPU's current treatment of datacenter vs consumer ASNs — the whole DC/consumer correction
  rests on this; confirm with fresh probes, don't assume.
- Current Russian legal exposure for running a sensor / recruiting a volunteer (active, changing
  legislation).
- OONI and Censored Planet current API shapes before writing Phase 0 ingest.
