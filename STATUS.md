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

**Caveats / not fully closed:** the on-wire RST path has been run only via the fake-reset unit
test — the real AF_PACKET capture (rig RST case) has **not been executed here** (no root + no `tc`
on this WSL box), so run `sudo rig/netns-calibrate.sh` on a suitable box to confirm end-to-end.
`DEFAULT_CONTROL_TTL` is a fixed 64, not yet calibrated per route. `watch_for_rst` currently
matches any RST in the namespace (no port filter) — fine in the isolated rig, needs a filter for
shared vantages. `payload_mutated` still validated only synthetically; `WeightedBundle::verify_stub`
is a placeholder (real ed25519 with the control plane, Phase 2).

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
| Wire `watch_for_rst` into `probe_battery` (on-wire `injected_rst`) | **Done.** Wiring unit-tested (fake reset → `injected_rst_at_sni`); real capture runs under the rig. |
| Run the netns rig under root (RST + throttle end-to-end) | **Not yet run here** — needs root + `tc`; this WSL box has neither. |
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

1. **Build Phase 1 step 0** — the netns/loopback fault-injection calibration harness (ECHO.md §7).
   The first runnable thing; proves the pipeline against ground truth before spending on VPSes.
2. Provision the RU/non-RU VPS pair; run the calibrated probe battery live.
3. Stand up the OONI-residential vs DC-VPS reachability comparison and fold it into the Phase 1
   write-up as the directional DC-vs-consumer gap read.
