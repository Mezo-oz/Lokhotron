# Lokhotron — STATUS

> **Living sitrep. Keep it current.** Update this whenever a decision changes, a phase advances,
> or an open question closes. Last updated: 2026-09-09 (transport enum reconciled against
> amnezia-client; screens re-run same-day — shortlist unchanged and clear to rent, but the
> **telegram gap flipped sign**, so Correction 3's sign-flip property does not hold this month).
> Prior: 2026-09-01 (re-ran both pre-spend screens — runbook
> step 1 — before renting: OFAC gate unchanged since 2026-08-27, Aeza still SDN-designated and the
> control case still fires, MTW/Timeweb/Beget still clear; OONI path profiles still Beget near-clean
> / Timeweb protocol-selective / MTW consumer-like, Correction-3 sign-flip intact. Prior: 2026-08-29
> keyed echo protocol, rig 8/8). **Everything that can be done without renting hosts is done — the
> next step is provisioning, and the pre-spend screens are fresh as of today.**

## What it is

A distributed measurement system that learns what the Russian TSPU is doing per operator/region
in near-real-time and pushes signed "use this transport here" intelligence to circumvention
clients inside Russia, so the fleet heals from a new block within minutes. Core primitive:
measure the *delta* (what a sensor sent vs. what a server you control received); the *shape* of
the difference is a diagnosis, not pass/fail. The live-adversary sibling of the `dpi-bench`
differential technique.

## Repo

`github.com/Mezo-oz/Lokhotron` — public, MIT. Design settled; **Phase 1 scaffold + TCP increment
built and verified** (WSL cargo 1.98): `cargo build --workspace` + `cargo clippy` clean, **53
tests pass** (16 lok-wire + 6 lok-contract + 9 lok-capture + 22 calibration incl. real loopback
end-to-end).

Run the suite with **`sudo rig/netns-test.sh`**, which runs it inside a private network namespace.
The loopback cases are the ones that prove probe and classifier agree on ground truth, so they must
not be the ones skipped when the host's loopback is unusable — this WSL instance swallows IPv4
loopback UDP specifically (TCP to `127.0.0.1` works, `::1` works, UDP to `127.0.0.1` vanishes),
which fails every UDP case for a reason that has nothing to do with the code.

Crates: `lok-contract` (Verdict/Observation/EchoIntegrity/Transport/TelemetryReport/WeightedBundle
— types + `sample`/`verify_stub`), **`lok-wire`** (the keyed v2 datagram both ends agree on:
in-tree HMAC-SHA-256 against RFC 4231 vectors, keyed per-marker payloads, and `classify_echo` →
intact / mutated-per-leg / reflected / unauthenticated), `echo-server` (marked-echo UDP **+ TCP
byte-echo**; admits only key-authenticated runs; FaultPolicy = calibration fault-emulation only),
`probe` (`classify` pure fn; keyed UDP `probe_once`; **`tcp_reachable` + `measure_throughput` +
`probe_battery`**; bind-before-connect `BoundTcpSocket` so the capture can be flow-scoped;
`tests/calibration.rs`), `lok-capture` (`AfPacketCapture` +
**`FlowFilter`/`rst_from_flow`/`peer_ttl_from_flow`** + `watch_for_rst` + `parse_ipv4_tcp_rst` +
`ipv4_from_frame` + `is_ttl_anomalous`), `rig/netns-calibrate.sh` (**eight cases**, all on real
kernel-injected faults), `rig/netns-test.sh` (the test suite in a private netns).

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
calibrated ~64); `nft` raw-payload rewrite mid-path → `payload_mutated`; a rewrite of the probe's
own header → `payload_mutated`, not a drop; and two **negative cases** — a foreign flow's mangled
RSTs in the air during a healthy run → still `ok`, and a reflector bouncing the probe back →
`udp_class_drop`, not `ok`. All eight PASS.

**Every new case is confirmed as a real regression before it is added**, not decoration: the
pre-change binaries are run against the same injected fault in a detached worktree and the wrong
verdict they produce is recorded. A case that passes on both sides of a change proves nothing. So
far that has caught four *fabricated findings* — `injected_rst_at_sni` on a healthy path, blindness
to a payload rewrite, `udp_class_drop` on a path that delivered everything, and `ok` on a path the
server never received — which is the class of failure that would make this instrument worse than
having no instrument.

**Closed since (2026-08-27):** captures are **flow-scoped**. `FlowFilter` pins peer IP, peer port,
our port and protocol; the probe binds its TCP socket (`BoundTcpSocket`, bind-before-connect via
libc — `std` has no such API) and its UDP socket *before* opening the capture, so the filter can
name a real local port instead of a wildcard. `payload_mutated` is now on the wire: each datagram
carries a known payload block, the payload is a function of the marker (recomputed, not retained;
a replay into another marker's slot is still a mismatch), and the rig rewrites a byte mid-path with
`nft` raw-payload set — the kernel fixes the UDP checksum, exactly as a real middlebox must.
*(Superseded on 2026-08-29: the payload is now keyed and the layout is v2 — see below and ECHO
§2a. The offsets in this paragraph no longer apply.)*

**Closed since (2026-08-29): the echo protocol is keyed** ([ECHO.md](ECHO.md) §2a, crate
`lok-wire`). Two shapes that produced a *wrong* verdict rather than a missing one, both confirmed
against the pre-change binaries in a detached worktree before the fix was called a fix:

- **A rewritten header read as a drop.** Rewriting the marker mid-path made the echo unrecognizable,
  and the pre-change probe reported `udp_class_drop` — "UDP is dead on this path" — against a path
  that delivered all eight datagrams. The 32-byte payload is now `HMAC(K, nonce‖marker‖session)`, so
  it identifies the datagram on its own; a destroyed header no longer destroys the evidence, and the
  rewrite reads as `payload_mutated`.
- **Delivery could be faked.** With a public payload function, anything on the path could echo the
  probe's own datagram back and be scored as an arrival: against a dumb verbatim reflector the
  pre-change probe reported **`ok`** — a clean bill of health for a path where the server received
  nothing. Request and response tags are now different HMACs, so an arrival means the far end signed
  it. An echo that is attributable but unsigned is counted (`EchoIntegrity`) and never scored as
  delivery.

Two things fell out that weren't the goal. The server now answers **only** authenticated datagrams,
so it is not an open UDP reflector on a public IP — which on a rented box is an abuse report and a
provider null-route away from looking exactly like a censorship finding. And because the server
signs *what it received*, which of the four (header, payload) × (as-sent, as-received) tag
combinations verifies tells you **which leg** a rewrite happened on.

**Caveats / not fully closed:** a *forward-leg* rewrite of the 20 bytes that authenticate the run
(nonce, session, session tag) still reads as a drop — the server discards it unanswered, which is
the deliberate price of not being a reflector. A mismatched key is indistinguishable from a total
block, so `deploy/sensor-setup.sh` ends in a pre-flight run and refuses to enable the timer unless
it comes back `ok` (`LOK_FORCE_ENABLE=1` to override). IPv4 only in the capture path (`peer_v4`
returns `None` on v6 and the battery falls back to the default control TTL). Mutation *leg* is
reported to the operator on stderr — `run-battery.sh` now keeps it beside the row (`"stderr"`
field) instead of discarding it — but it has no home in the contract yet; promote it when the
collector exists. `WeightedBundle::verify_stub` is a placeholder (real ed25519 with the control
plane, Phase 2). This is all still **lab** ground-truth — the next real milestone is a live
RU/non-RU VPS pair.

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
| Phase 1 **step 0** (calibration harness) | **Built + green** — 49 tests pass, clippy clean. |
| Phase 1 TCP increment (real reachability + throughput) | **Done + green.** |
| Wire `watch_for_rst` into `probe_battery` (on-wire `injected_rst`) | **Done + verified on the wire** (rig, root). |
| Per-route control-TTL calibration | **Done + verified** — RST judged against measured ~64, not assumed. |
| Run the netns rig under root | **Passed 8/8** on real kernel-injected faults (WSL Ultramarine; 4 cases 2026-08-26, payload-mutation + foreign-RST 2026-08-27, header-rewrite + reflector 2026-08-29). |
| Flow-scoped capture (5-tuple filter) | **Done + verified on the wire** — foreign RSTs no longer contaminate a clean verdict (rig case 6). |
| On-wire `payload_mutated` | **Done + verified on the wire** — keyed payload block + `nft` raw-payload rewrite mid-path (rig case 5). |
| Keyed echo protocol (`lok-wire`) | **Done + verified on the wire** — a rewritten header is recovered, not reported as a drop (rig case 7); a reflector cannot fake delivery (rig case 8). Both confirmed as real regressions against the pre-change binaries. |
| Key provisioning + the mismatched-key foot-gun | **Done** — generated by `server-setup.sh`, carried to sensors, and gated by a pre-flight run that refuses to enable the timer unless it comes back `ok`. |
| Repeatable deploy for the VPS pair (`deploy/`) | **Built** — provider-agnostic setup scripts + systemd units + `DEPLOY.md`. Not yet run on real hosts. |
| RU legal / sanctions check | **Done** — [deploy/LEGAL-RU.md](deploy/LEGAL-RU.md). Research pass, not advice; re-read at rent time. |
| Provider screen (OFAC + OONI) | **Done** — [phase0/PROVIDER-SHORTLIST.md](phase0/PROVIDER-SHORTLIST.md). 22 candidates; Aeza designated; 3 suggested spanning path profiles. |
| Provision + live run | **NEXT — operator step.** Everything upstream is unblocked; see the runbook below. |
| Phase 0 (kept, narrowed: OONI-residential vs DC-VPS reachability diff = recruitment-free gap read) | **Done (first read).** `phase0/ooni_gap.py` + [FINDINGS-2026-08-27](phase0/FINDINGS-2026-08-27.md). The gap is real but **provider-specific**, not a constant — which turned provider choice into a measurement decision. |
| Phase 1 (2 VPS + live probe battery + echo delta) | Not started. Honest claim scoped to the **DC path** until a consumer vantage exists. |
| Phase 2 (analysis + signed bundle push) | Not started. |
| Phase 3 (client-as-sensor fusion — the only clean gap-closer) | Not started. |

## Open before hardening (verify, don't trust from memory)

- ~~TSPU's current DC-vs-consumer treatment~~ — **first read done** (2026-08-27,
  [phase0/FINDINGS-2026-08-27.md](phase0/FINDINGS-2026-08-27.md)). Correction 3 stands and is
  sharper than stated: within RU hosting ASNs the block rate spreads **87-96 pp on every test**
  (Beget near-clean across Tor/Psiphon/Telegram while consumer operators sit at 75-99%), and the
  gap's *sign* flipped by test (Psiphon +65 pp consumer-vs-DC, Telegram -7.9 pp). So the risk isn't
  that a VPS is a lenient sensor — it may be an unrelated one. **Consequence: which RU provider you
  rent decides what you can measure.**

  **The sign flip is month-specific and is gone as of 2026-09-09** — telegram read −2.7 pp on
  09-01 and **+6.4 pp** today, both with disjoint intervals, so this is a real move rather than a
  CI wobble. All three tests now point the same way (tor +8.3, psiphon +62.0, telegram +6.4).
  Correction 3 itself is unaffected and if anything cleaner: the load-bearing evidence is the
  spread *between* hosting providers, and that is intact — within the DC bucket today, Beget sits
  at 13.6% on `tor` against Timeweb's 99.3%, ~86 pp apart. Treat "DC is uniformly more lenient"
  as this month's shape, not a property. Re-run before provisioning; the picture is month-specific
  and has now demonstrably changed twice.
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
- ~~Concrete transport enum must track amnezia-client's real transport set~~ — **done
  2026-09-09**, read from amnezia-client `dev` (`containerEnum.h`, `protocolEnum.h`,
  `containerUtils.cpp`, `protocolConstants.h`). The draft guess named two transports the client
  cannot speak: `ss2022` (Amnezia's Shadowsocks cipher is `chacha20-ietf-poly1305`; no
  `2022-blake3-*` exists in the tree) and `obfs4` (Tor's, not Amnezia's — their OpenVPN
  obfuscation is Cloak). It also treated REALITY as a transport when it is one of three security
  modes on the XRay container, and amnezia-client refuses to pair it with mKCP. New set is nine
  entries, tabled in CONTRACT.md; added WireGuard, OpenVPN and IKEv2 as *positive* controls, all
  three DPI-obvious by Amnezia's own description. **The axis is wire fingerprint, not container
  inventory** — `Awg2` is a separate container mapping to the same `Proto::Awg`, so it needs no
  variant. Also fixed an interop bug found on the way: CONTRACT.md published `amneziawg` /
  `plain-tls-control` while `rename_all = "snake_case"` emitted `amnezia_wg` /
  `plain_tls_control`, and nothing compared them. Wire names are now pinned per variant with a
  test that fails on exactly that mismatch (verified against the old spelling).
- **Verdict vocabulary ↔ dpi-bench property vocabulary** — first pull done 2026-09-04: dpi-bench's
  third state (`exit 2`, "cannot judge") became `not_evaluated` (contract 0.2). Its byte-level
  properties were checked and don't transfer (they describe zapret2's dissector, not the TSPU).
  Further pulls stay one-way and non-blocking; dpi-bench is a separate session.
- Name invariant: "Lokhotron"/лохотрон never appears in any client-facing artifact or contract
  payload that reaches the client. Safe only because the trust boundary keeps it censor-facing.

## Next actions

**Everything that does not require a rented host is done.** What remains is the provisioning
runbook below, in order. Steps 1-3 are an afternoon; step 4 is the week that tests the thesis.

1. **Re-run both screens before spending anything.** Sanctions designations and TSPU filtering
   each move month to month, and both outputs are dated snapshots:
   `python phase0/provider_screen.py` and `python phase0/ooni_gap.py`. If a provider's OFAC status
   or path profile changed, the shortlist changes with it.
   **Re-run 2026-09-01** ([phase0/PROVIDER-SCREEN-2026-09-01.md](phase0/PROVIDER-SCREEN-2026-09-01.md),
   [phase0/gap-2026-09-01.md](phase0/gap-2026-09-01.md)): nothing flipped. Aeza still SDN-designated
   (control fires → screen not broken); MTW/Timeweb/Beget still clear (MTW's 4 hits are the same
   generic `ekspert` token collisions, prior-cleared). Path profiles hold: Beget near-clean
   (tor 16% / psiphon 3.7% / telegram 7.4%), Timeweb selective (99.6% / 7.9% / 98.6%), MTW
   consumer-like (psiphon 78%); Correction-3 sign-flip intact (psiphon +64pp, telegram −2.7pp,
   tor +7.7pp). **Shortlist unchanged — clear to rent.** Re-run again if more than a few weeks pass
   before provisioning.
   **Re-run 2026-09-09** ([phase0/PROVIDER-SCREEN-2026-09-09.md](phase0/PROVIDER-SCREEN-2026-09-09.md),
   [phase0/gap-2026-09-09.md](phase0/gap-2026-09-09.md)): sanctions picture unchanged — Aeza still
   fires 3 SDN hits (control good), Timeweb and Beget still no match, MTW still the same 4
   `ekspert` token collisions, none of which is MTW. Path profiles hold: Beget near-clean
   (tor 16.0% / psiphon 3.7% / telegram 7.4%), Timeweb selective (99.6% / 9.0% / 98.4%), MTW
   consumer-like (psiphon 79.7%). **Shortlist still clear to rent.** The one change is the
   telegram gap sign flip described above — it does not affect which providers to buy, only what
   the Phase 0 read is allowed to say about DC-vs-consumer shape.

2. **Rent.** One non-RU echo server (anywhere outside RU with a stable public IP) and **2-3 RU
   sensors at different providers** — the spread between RU hosting providers is 87-96 pp, so one
   box cannot be called representative. Current suggestion, chosen to span path profiles:
   **MTW** (consumer-like), **Timeweb** (protocol-selective, best characterised), **Beget**
   (near-clean control). **Aeza is OFAC-designated — do not transact.** Rent in your own name with
   accurate details; OFAC-screen the provider, its parent and affiliates at purchase, and again at
   renewal. Full reasoning: [deploy/LEGAL-RU.md](deploy/LEGAL-RU.md).

3. **Provision** ([deploy/DEPLOY.md](deploy/DEPLOY.md)). `server-setup.sh <bind>:47017` on the
   non-RU box, `sensor-setup.sh <server-ip>:47017 <interval> <count>` on each sensor; open the port
   in both the host firewall and the provider security group. Then two pre-flight checks that are
   easy to skip and expensive to get wrong:
   - **Verify the assigned IP's real ASN** and set `ASN=` / `REGION=` in `/etc/lokhotron/sensor.env`
     (the setup script writes it from `deploy/lokhotron-sensor.env.example` and warns you). The ASN
     carrying OONI signal is often not the one a plan lands in (FirstByte: n=2,102 on AS205090,
     n=1 on its others). A wrong tag mislabels every verdict the sensor ever produces.
   - **Confirm every probe target is a host we own.** This is the hard rule the legal read rests
     on — third-party probing is where Art. 274.1 would land — and it is a one-line check of the
     env file before the timer is enabled.

4. **Run the battery live for a week, and watch the `timeout_indistinct` rate.** The instrument is
   calibrated 8/8 against kernel-injected faults, so a blank is now a *finding* ("the TSPU is
   uniform at this granularity") rather than "our tool is blind" — that two-sided honesty is what
   the calibration bought. It holds only for rows that are measurements: `run-battery.sh` records a
   sensor that could not run (binary, config, `CAP_NET_RAW`, probe crash/timeout, echo host refusing)
   as `not_evaluated`, never as `timeout_indistinct`, and re-checks on every tick rather than once
   at install. Exclude those rows from every rate and watch their count as sensor health — a wall of
   them is a dead box, not a uniform TSPU. The one silence the sensor cannot classify is "echo
   server down vs. wrong key vs. real total block": settle that from the server's journal and from
   whether all three sensors went quiet at the same instant. Compare the three sensors against
   each other: divergence between providers is itself the Correction 3 result, measured on our
   own instrument instead of inferred from OONI.

5. **Fold the results back.** A draft write-up already exists at
   [writeups/net4people-2026-08-draft.md](writeups/net4people-2026-08-draft.md) — it covers the
   calibrated instrument and the Phase 0 read, with the live-run sections marked *(pending)*. It is
   postable **now** as a method-critique post (getting the TTL-anomaly test and the verdict
   vocabulary reviewed before spending the week is worth more than posting after), or after the run
   with the results filled in. Either way read its "notes for the author" first: the provider-naming
   call, and that publishing is the layer carrying the RU legal exposure. Feed the live numbers into `phase0/ooni_gap.py --dc-measurements` for
   the apples-to-apples consumer-vs-our-DC comparison DESIGN.md actually asks for, and write up
   Phase 1 with the claim scoped to *this provider's* DC path plus the OONI comparison as the
   directional gap read. Publishable on its own (net4people).

6. **(Phase 2, gated on the delta proving informative.)** Reconcile the transport enum with
   amnezia-client's real set; decide whether the bundle channel rides amnezia's config-update path;
   replace `WeightedBundle::verify_stub` with real ed25519.

### Recently closed

- **Infrastructure failure is no longer a censorship finding** (2026-09-04) — `Verdict::NotEvaluated`
  (contract 0.2, closed `reason` set) and a per-run liveness gate in `deploy/run-battery.sh`; the
  probe's stderr is kept beside the row instead of thrown away. Every branch exercised against the
  real probe + echo server. The dpi-bench inheritance that did transfer.

- **The keyed echo protocol** (2026-08-29) — the two shapes that made the instrument report
  something *false* rather than nothing: a rewritten header read as a drop, and a reflector read as
  a healthy path. Rig 8/8, and both confirmed as real regressions against the pre-change binaries.
- Phase 1 step 0 calibration harness — built, and verified on the wire.
- Flow-scoped capture and on-wire `payload_mutated` — the two shared-vantage caveats that would
  have produced fabricated findings on a rented box.
- Phase 0 gap read, RU legal/sanctions check, and the provider screen — see the phase table.
