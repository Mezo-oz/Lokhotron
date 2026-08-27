# Lokhotron — STATUS

> **Living sitrep. Keep it current.** Update this whenever a decision changes, a phase advances,
> or an open question closes. Last updated: 2026-08-27 (flow-scoped capture + on-wire payload mutation, rig now 6 cases; Phase 0 gap read run).

## What it is

A distributed measurement system that learns what the Russian TSPU is doing per operator/region
in near-real-time and pushes signed "use this transport here" intelligence to circumvention
clients inside Russia, so the fleet heals from a new block within minutes. Core primitive:
measure the *delta* (what a sensor sent vs. what a server you control received); the *shape* of
the difference is a diagnosis, not pass/fail. The live-adversary sibling of the `dpi-bench`
differential technique.

## Repo

`github.com/Mezo-oz/Lokhotron` — public, MIT. Design settled; **Phase 1 scaffold + TCP increment
built and verified** (WSL cargo 1.98): `cargo build --workspace` + `cargo clippy` clean, **30
tests pass** (2 lok-contract + 9 lok-capture + 19 calibration incl. real loopback end-to-end).

Crates: `lok-contract` (Verdict/Observation/Transport/TelemetryReport/WeightedBundle — types +
`sample`/`verify_stub`), `echo-server` (marked-echo UDP **+ TCP byte-echo**; DropPolicy =
calibration fault-emulation only), `probe` (`classify` pure fn; UDP `probe_once` with a known
payload block; **`tcp_reachable` + `measure_throughput` + `probe_battery`**; bind-before-connect
`BoundTcpSocket` so the capture can be flow-scoped; `tests/calibration.rs`), `lok-capture`
(`AfPacketCapture` + **`FlowFilter`/`rst_from_flow`/`peer_ttl_from_flow`** + `watch_for_rst` +
`parse_ipv4_tcp_rst` + `ipv4_from_frame` + `is_ttl_anomalous`), `rig/netns-calibrate.sh`
(**six cases**, all on real kernel-injected faults).

**Closed:** real `tcp_reachable` (a full UDP blackout with TCP up reads `udp_class_drop`; TCP-down
reads `timeout_indistinct` instead of masking); real bulk throughput → `throttle_to_rate`; and
**`injected_rst_at_sni` on the wire** — `watch_for_rst` is wired into `probe_battery` behind a
`TcpProbe` seam (`CapturingTcpProbe` on Linux+root, degrades to `PlainTcpProbe` without
`CAP_NET_RAW`), populating `Observation.rst` from a captured RST whose TTL is judged against
`DEFAULT_CONTROL_TTL`. The wiring is unit-tested with a fake reset; the live capture is the rig's
RST case.

Control TTL is now **calibrated per route** (`calibrate_control_ttl`): the battery sends a UDP
datagram to the peer and captures the echoed reply's TTL over the same path, judging the RST
against that measured value; `DEFAULT_CONTROL_TTL` (64) is only a fallback when capture is
unavailable.

**Verified end-to-end on real packets** (`sudo rig/netns-calibrate.sh`, WSL Ultramarine): clean →
`ok`; drop-from-4 → `silent_drop_from_segment{n:4}`; `tc tbf` 128 kbit → `throttle_to_rate`
(measured ~124 kbit); `nft`-mangled RST (TTL 200) → `injected_rst_at_sni` (judged against the
calibrated ~64); `nft` raw-payload rewrite mid-path → `payload_mutated`; and the **negative case**
— a foreign flow's mangled RSTs in the air during a healthy run → still `ok`. All six PASS.

**Both new cases were confirmed as real regressions**, not decoration: the pre-change binaries,
run against the same rig in a detached worktree, reported `ok` for the mutated-payload case (blind
to it) and `injected_rst_at_sni` for the foreign-RST case — a *fabricated finding on a healthy
path*, which is the single worst thing this instrument could do live.

**Closed since (2026-08-27):** captures are **flow-scoped**. `FlowFilter` pins peer IP, peer port,
our port and protocol; the probe binds its TCP socket (`BoundTcpSocket`, bind-before-connect via
libc — `std` has no such API) and its UDP socket *before* opening the capture, so the filter can
name a real local port instead of a wildcard. `payload_mutated` is now on the wire: each datagram
carries `[nonce][marker][32 bytes of known payload]`, the payload is a deterministic function of
the marker (recomputed, not retained; a replay into another marker's slot is still a mismatch),
and the rig rewrites a byte mid-path with `nft @th,128,8 set` — the kernel fixes the UDP checksum,
exactly as a real middlebox must.

**Caveats / not fully closed:** a rewrite of the *nonce or marker* still reads as a drop, not
`payload_mutated` — the datagram stops being recognizable as ours. Closing that needs the keyed
marker scheme (ECHO §2), not this MVP. IPv4 only in the capture path (`peer_v4` returns `None` on
v6 and the battery falls back to the default control TTL). `WeightedBundle::verify_stub` is a
placeholder (real ed25519 with the control plane, Phase 2). This is all still **lab** ground-truth
— the next real milestone is a live RU/non-RU VPS pair.

## Three-tree architecture (a security boundary, not tidiness)

1. `dpi-bench` (`X:\DPI-Tester`) — offline zapret2 harness, teaches the capture/diff primitive on
   a lab target. Exists.
2. **Lokhotron** (this repo) — the sensing layer: probe, reverse-measurement server, collector,
   control plane. Your infrastructure (Rust/Python/SQL on Linux VPSes). One workspace, multiple
   crates. **Build now.**
3. The **client** — ships to Android phones; kept in a *separate* tree so an adversary
   reverse-engineering the app can't extract the endpoint inventory, dark canaries, or
   control-plane logic. Credible home is **amnezia-client upstream**, not a repo we own (inherits
   its trust anchor). Design notes at `X:\Lokhotron-client\DISTRIBUTION.md`, deliberately outside
   the repo.

The only thing crossing the #1↔#2 boundary is a **versioned spec** ([CONTRACT.md](CONTRACT.md)),
not shared code: verdict vocabulary + k-anon telemetry schema (#2→#1) + signed weighted-mix
bundle format (#1→#2).

## Key design decisions locked in (corrections to the original concept)

- **Control plane is a targeting oracle** — signing stops forgery, not *disclosure*. Bundles
  carry a **weighted distribution over surviving transports that the client samples**, never an
  argmax (argmax = fleet monoculture = ideal monitoring target). Plus **dark endpoints** never
  named in any bundle, as the only detector for a Potemkin clean-path.
- **dpi-bench inheritance is narrow** — the reassembler does *not* transfer (the live server is a
  real endpoint). What transfers is the property-vocabulary method → the **verdict vocabulary**.
  Byte-diff only earns its keep on selective-drop / payload-mutation; its MVP is a
  **sequence-marked echo protocol**, not a diff engine.
- **DC-vs-consumer gap is the central constraint** — a cheap RU VPS may sit behind a different
  box or none, so its signal can be categorically wrong. This makes **client-as-sensor the
  unlock, not the capstone**, which forces the k-anon telemetry schema + edge-aggregation
  (collector can't de-anon even under coercion) to be specced day one.
- **Phase 0/1 inverted** — Phase 1 (one RU VPS + one non-RU VPS + probe battery, ~$10/mo weekend)
  is the thesis test and a net4people-publishable deliverable on its own. Phase 0 (OONI/Censored
  Planet ingest) shrinks to a ≤1-week context layer.

## Founding principle (non-negotiable, binds both trees)

> The client never runs on anyone who did not install it. Deniability is a capability given to an
> informed user, never a state of ignorance imposed on them.

No worm, no covert install. Android duress design = PanicKit (fork if needed) → crypto-erase
keys; recommend GrapheneOS duress PIN for the high-risk tier. Full rationale in
`X:\Lokhotron-client\DISTRIBUTION.md`.

## Sequencing decision (locked)

Do **not** gate Lokhotron on finishing dpi-bench — the inheritance is narrow (Correction 2), so
gating just spends weeks not knowing if the bet holds. The two are **independent parallel tracks**
(dpi-bench runs in its own session). The ground-truth safety net comes instead from **Phase 1 step
0**: a local fault-injection calibration harness that proves the echo protocol + capture +
classifier against known-injected verdicts before any live run. See [ECHO.md](ECHO.md) §7.

## Phase status

| Phase | State |
|---|---|
| Design | **Done** — DESIGN + CONTRACT + ECHO + this file committed. |
| Phase 1 **step 0** (calibration harness) | **Built + green** — 21 tests pass. |
| Phase 1 TCP increment (real reachability + throughput) | **Done + green.** |
| Wire `watch_for_rst` into `probe_battery` (on-wire `injected_rst`) | **Done + verified on the wire** (rig, root). |
| Per-route control-TTL calibration | **Done + verified** — RST judged against measured ~64, not assumed. |
| Run the netns rig under root (RST + throttle end-to-end) | **Passed** — all 4 cases PASS on real kernel-injected faults (WSL Ultramarine, 2026-08-26). |
| Flow-scoped capture (5-tuple filter) | **Done + verified on the wire** — foreign RSTs no longer contaminate a clean verdict (rig case 6). |
| On-wire `payload_mutated` | **Done + verified on the wire** — known payload block + `nft` raw-payload rewrite mid-path (rig case 5). |
| Repeatable deploy for the VPS pair (`deploy/`) | **Built** — provider-agnostic setup scripts + systemd units + `DEPLOY.md`. Not yet run on real hosts. |
| Provision + live run | **Operator step** — create hosts, RU legal check, run setup, fill tags. |
| Phase 0 (kept, narrowed: OONI-residential vs DC-VPS reachability diff = recruitment-free gap read) | **Done (first read).** `phase0/ooni_gap.py` + [FINDINGS-2026-08-27](phase0/FINDINGS-2026-08-27.md). The gap is real but **provider-specific**, not a constant. |
| Phase 1 (2 VPS + live probe battery + echo delta) | Not started. Honest claim scoped to the **DC path** until a consumer vantage exists. |
| Phase 2 (analysis + signed bundle push) | Not started. |
| Phase 3 (client-as-sensor fusion — the only clean gap-closer) | Not started. |

## Open before hardening (verify, don't trust from memory)

- ~~TSPU's current DC-vs-consumer treatment~~ — **first read done** (2026-08-27,
  [phase0/FINDINGS-2026-08-27.md](phase0/FINDINGS-2026-08-27.md)). Correction 3 stands and is
  sharper than stated: within RU hosting ASNs the block rate spreads **87-96 pp on every test**
  (Beget near-clean across Tor/Psiphon/Telegram while consumer operators sit at 75-99%), and the
  gap's *sign* flips by test (Psiphon +65 pp consumer-vs-DC, Telegram -7.9 pp). So the risk isn't
  that a VPS is a lenient sensor — it may be an unrelated one. **Consequence: which RU provider you
  rent decides what you can measure.** Re-run the read before provisioning; the picture is
  month-specific.
- ~~Current Russian legal exposure for running a sensor / recruiting volunteers~~ — **research
  pass done** (2026-08-27, [deploy/LEGAL-RU.md](deploy/LEGAL-RU.md); not legal advice, re-read at
  rent time). Sensing-layer RU exposure is low *conditional on a hard rule*: the battery only ever
  targets a host we own (third-party probing is where Art. 274.1, 2-6 years, would land). The real
  RU exposure is on the **publishing** side (March 2024 dissemination ban; 8,700+ sites blocked by
  Apr 2025; Roskomsvoboda designated a foreign agent and shut down Sept 2025) — which is exactly
  what the three-tree split isolates. **Sharpest near-term risk is US sanctions, not RU law:** OFAC
  designated RU hoster **Aeza Group** on 2025-07-01, SDN transactions are strict liability, and
  `phase0/asn_classes.json` lists `aeza` as a hosting brand — measurement-eligible is not
  procurement-eligible. OFAC-screen every candidate provider before paying. Volunteer recruitment
  stays deferred to Phase 3 client-as-sensor.
- ~~OONI current API shapes / which RU reachability tests are populated~~ — **answered**
  (`api.ooni.io/api/v1/aggregation`, `axis_x=probe_asn`, live and well-populated: psiphon 79k,
  telegram 45k, tor 45k, torsf 1.2k, riseupvpn 322 over 30 days; `vanilla_tor` unusable, ~95%
  failures). Censored Planet shapes still unverified — not needed for the gap read.
- Concrete transport enum must track amnezia-client's real transport set, not the draft guess.
- **Verdict vocabulary ↔ dpi-bench property vocabulary** — reconcile once dpi-bench firms up
  (one-way pull into CONTRACT Part 1; not a blocker; dpi-bench is a separate session).
- Name invariant: "Lokhotron"/лохотрон never appears in any client-facing artifact or contract
  payload that reaches the client. Safe only because the trust boundary keeps it censor-facing.

## Next actions

1. ~~Build Phase 1 step 0 (calibration harness)~~ — **done + verified on the wire, 6/6 cases.**
   The two shared-vantage caveats that would have mattered on a rented box are closed.
2. **Provision the RU/non-RU VPS pair and run the battery live.** The repeatable deploy is built
   (`deploy/` — `server-setup.sh`, `sensor-setup.sh`, systemd units, `DEPLOY.md`). Remaining is
   the part only the operator can do: create two hosts, do the **RU legal/risk check**, pick
   providers, run the two setup scripts, fill in ASN/REGION. This is the week that tests the
   thesis — watch the `timeout_indistinct` rate; a calibrated blank is now a real finding.
3. ~~Stand up the OONI-residential vs DC-VPS reachability comparison~~ — **done**; it lives in
   `phase0/` and folds into the Phase 1 write-up as the directional gap read. Two things it hands
   forward: **rent 2-3 RU VPSes at different providers** rather than one (the spread makes a single
   box unrepresentative, and it is still inside the ~$10/mo envelope), and once a sensor is live,
   feed its results back in via `--dc-measurements` for the apples-to-apples version.
4. (Phase 2, gated on the delta proving informative) reconcile the transport enum with
   amnezia-client's real set; decide whether the bundle channel rides amnezia's config-update path.
