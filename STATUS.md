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

`github.com/Mezo-oz/Lokhotron` — public, MIT. Design settled; **Phase 1 scaffold built and
verified** (WSL cargo 1.98): `cargo build --workspace` + `cargo clippy` clean, **14 tests pass**
(2 lok-contract + 2 lok-capture + 10 calibration incl. one real loopback end-to-end). Next
increment: the TCP-handshake probe (see below).

Crates: `lok-contract` (Verdict/Observation/Transport/TelemetryReport/WeightedBundle — types +
`sample`/`verify_stub`), `echo-server` (marked-echo UDP; DropPolicy = calibration fault-emulation
only), `probe` (`classify` pure fn + UDP `probe_once` + `tests/calibration.rs`), `lok-capture`
(`AfPacketCapture` + `parse_ipv4_tcp_rst`), `rig/netns-calibrate.sh` (clean + UDP-drop cases run
today; RST/throttle stubbed pending the TCP probe).

**Deliberately stubbed (not done):** probe is UDP-only, so `tcp_reachable` is hardcoded `true`
(a full UDP blackout currently misclassifies as `udp_class_drop`); no throughput measurement
(`throttled` is synthetic-only); `injected_rst`/`payload_mutated` validated only via synthetic
Observations; `WeightedBundle::verify_stub` is a placeholder (real ed25519 with the control
plane); `AfPacketCapture` compiles but isn't wired to a live probe path.

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
| Phase 1 **step 0** (calibration harness) | **Built + green** — 14 tests pass; netns rig clean+UDP-drop cases run. |
| Phase 1 next increment (TCP-handshake probe + wire lok-capture + throughput) | **Next.** Not started. |
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
