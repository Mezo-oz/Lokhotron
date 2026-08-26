# Lokhotron — STATUS

> **Living sitrep. Keep it current.** Update this whenever a decision changes, a phase advances,
> or an open question closes. Last updated: 2026-08-26 (added ECHO.md protocol spec; sequencing + calibration + gap-read folded in).

## What it is

A distributed measurement system that learns what the Russian TSPU is doing per operator/region
in near-real-time and pushes signed "use this transport here" intelligence to circumvention
clients inside Russia, so the fleet heals from a new block within minutes. Core primitive:
measure the *delta* (what a sensor sent vs. what a server you control received); the *shape* of
the difference is a diagnosis, not pass/fail. The live-adversary sibling of the `dpi-bench`
differential technique.

## Repo

`github.com/Mezo-oz/Lokhotron` — public, MIT. Design settled; **Phase 1 scaffold + TCP increment
built and verified** (WSL cargo 1.98): `cargo build --workspace` + `cargo clippy` clean, **20
tests pass** (2 lok-contract + 4 lok-capture + 14 calibration incl. real loopback end-to-end).

Crates: `lok-contract` (Verdict/Observation/Transport/TelemetryReport/WeightedBundle — types +
`sample`/`verify_stub`), `echo-server` (marked-echo UDP **+ TCP byte-echo**; DropPolicy =
calibration fault-emulation only), `probe` (`classify` pure fn; UDP `probe_once`; **`tcp_reachable`
+ `measure_throughput` + `probe_battery`**; `tests/calibration.rs`), `lok-capture`
(`AfPacketCapture` + `watch_for_rst` + `parse_ipv4_tcp_rst` + `ipv4_from_frame` + `is_ttl_anomalous`),
`rig/netns-calibrate.sh` (clean + UDP-drop + **throttle** run today; RST stubbed).

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
calibrated ~64). All four PASS.

**Caveats / not fully closed:** `watch_for_rst`/`observe_peer_ttl` match any packet from the peer
in the namespace (no 5-tuple filter) — fine in the isolated rig, needs a filter for shared
vantages. `payload_mutated` still validated only synthetically (no on-wire injector yet).
`WeightedBundle::verify_stub` is a placeholder (real ed25519 with the control plane, Phase 2).
This is all still **lab** ground-truth — the next real milestone is a live RU/non-RU VPS pair.

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
| Repeatable deploy for the VPS pair (`deploy/`) | **Built** — provider-agnostic setup scripts + systemd units + `DEPLOY.md`. Not yet run on real hosts. |
| Provision + live run | **Operator step** — create hosts, RU legal check, run setup, fill tags. |
| Phase 0 (kept, narrowed: OONI-residential vs DC-VPS reachability diff = recruitment-free gap read) | Not started. |
| Phase 1 (2 VPS + live probe battery + echo delta) | Not started. Honest claim scoped to the **DC path** until a consumer vantage exists. |
| Phase 2 (analysis + signed bundle push) | Not started. |
| Phase 3 (client-as-sensor fusion — the only clean gap-closer) | Not started. |

## Open before hardening (verify, don't trust from memory)

- TSPU's current DC-vs-consumer treatment — the OONI-residential vs DC-VPS diff is the first read;
  Correction 3 rests on it.
- Current Russian legal exposure for running a sensor / recruiting volunteers.
- OONI + Censored Planet current API shapes, and which residential RU reachability tests are
  populated for the operators of interest.
- Concrete transport enum must track amnezia-client's real transport set, not the draft guess.
- **Verdict vocabulary ↔ dpi-bench property vocabulary** — reconcile once dpi-bench firms up
  (one-way pull into CONTRACT Part 1; not a blocker; dpi-bench is a separate session).
- Name invariant: "Lokhotron"/лохотрон never appears in any client-facing artifact or contract
  payload that reaches the client. Safe only because the trust boundary keeps it censor-facing.

## Next actions

1. ~~Build Phase 1 step 0 (calibration harness)~~ — **done + verified on the wire.**
2. **Provision the RU/non-RU VPS pair and run the battery live.** The repeatable deploy is built
   (`deploy/` — `server-setup.sh`, `sensor-setup.sh`, systemd units, `DEPLOY.md`). Remaining is
   the part only the operator can do: create two hosts, do the **RU legal/risk check**, pick
   providers, run the two setup scripts, fill in ASN/REGION. This is the week that tests the
   thesis — watch the `timeout_indistinct` rate; a calibrated blank is now a real finding.
3. Stand up the OONI-residential vs DC-VPS reachability comparison and fold it into the Phase 1
   write-up as the directional DC-vs-consumer gap read.
4. (Phase 2, gated on the delta proving informative) reconcile the transport enum with
   amnezia-client's real set; decide whether the bundle channel rides amnezia's config-update path.
