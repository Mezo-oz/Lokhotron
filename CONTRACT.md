# Lokhotron — the contract (v0.2 draft)

The **only** thing that crosses the boundary between Lokhotron (tree #1, this repo) and the
client (tree #2, its own repo / Amnezia upstream). It is a **versioned spec, not a shared
library** — #1 owns and versions it; #2 implements it. Three parts:

1. **Verdict vocabulary** — the enumerated language of TSPU actions (both sides speak it).
2. **Telemetry schema** — outcomes flowing #2 → #1 (k-anon, edge-aggregated).
3. **Strategy-bundle format** — intelligence flowing #1 → #2 (signed, a weighted mix).

Design rules that hold across all three:
- **Least disclosure.** Nothing in a client-facing artifact reveals more than a client is allowed
  to know: no full endpoint inventory, no dark-canary identities, no other regions' data.
- **Signed, pinned, verified.** Everything #1 → #2 is signed; the key is pinned in the client.
  Same key-distribution problem as the client binary and the bootstrap — solved once.
- **Versioned.** Every artifact carries `contract_version`. Unknown major version → the client
  ignores it rather than guessing.

---

## Part 1 — Verdict vocabulary

A **closed, enumerated** taxonomy of what the TSPU did. Defined before any collection, because
free-form outcomes drown the analysis layer. This is dpi-bench's property-vocabulary method
pointed at the live adversary.

| verdict | meaning | observability | self-ID signal |
|---|---|---|---|
| `ok` | transport completed and carried traffic | either | — |
| `injected-rst-at-sni` | RST right after the TLS SNI | client-side | RST TTL / IP-ID mismatch vs real peer |
| `silent-drop-from-segment-N` | connection dies after segment N | needs delta | highest marker server saw = N-1 |
| `throttle-to-rate-R` | handshake ok, throughput collapses to ~R | client-side | sustained rate ceiling |
| `udp-class-drop` | UDP transport dies, TCP/443 survives same path | client-side | control transport comparison |
| `active-probe-observed` | a Reality probe was forwarded to the real cover site | **server-side only** | server log, no client signal |
| `payload-mutated` | bytes rewritten in flight | needs delta | server-received ≠ sensor-sent |

> **`payload-mutated` covers a rewrite of the probe's own header too.** On the wire that *is* a
> rewrite of UDP payload bytes like any other, and a client can act on "this path mangles bytes"
> but not on where inside our datagram it happened. Which part was rewritten, on which leg, and
> whether anything tried to fake delivery are **measurement-integrity** facts (`EchoIntegrity` in
> `lok-contract`, derivation in [ECHO.md](ECHO.md) §2a) — they say how much to trust a verdict,
> not what the transport suffered, so they are deliberately not verdicts. "Someone reflected our
> probe" describes the instrument's own channel, and the synthetic control probe's channel has no
> counterpart in a real transport.
| `timeout-indistinct` | died with no distinguishing shape | either | the null verdict — see note |
| `not-evaluated` | **no measurement was made** — the instrument could not run or could not be trusted | sensor-side | `reason` (closed set, below) — see note |

**`timeout-indistinct` is the honest failure mode.** If most blocks land here, the delta isn't
informative and the thesis is in trouble — that's the thing Phase 1 exists to find out in week
one. Track its rate as a first-class metric.

**`not-evaluated` is not a failure mode of the path — it is a failure mode of the sensor**, and it
is in the closed set (v0.2) precisely so nobody can forget to handle it. Every other verdict,
`timeout-indistinct` included, says *the probe ran and this is what the path did*. `not-evaluated`
says *the probe did not run, or ran without the capability that keeps its columns honest*, and
therefore says nothing about the TSPU. Before 0.2 the run wrapper recorded all of those as
`timeout-indistinct`, and a suspended box would have produced a week of "the TSPU is uniform at
this granularity". The `reason` is a closed enum, additive by minor version like the verdicts:

| reason | meaning |
|---|---|
| `probe_missing` | the probe binary is missing or not executable |
| `config_invalid` | sensor config unreadable, or lacks `SERVER` / a 64-hex `LOK_PROBE_KEY` (an unkeyed run cannot prove delivery) |
| `no_capability` | no `CAP_NET_RAW`, so the capture that tells an injected RST from a blackout could not exist — the run would have moved real RST-blocks into `timeout-indistinct` |
| `probe_error` | the probe exited non-zero before a verdict (bind failure, unresolvable address, ICMP port-unreachable from the echo *host*, killed on timeout); its stderr rides in `detail` |
| `malformed_verdict` | the probe printed something that is not a verdict this contract knows |

`detail` is optional free text for the operator — allowed *because* nothing aggregates on it.
Rules for consumers: **exclude `not-evaluated` from every verdict rate** (in `lok-contract`,
`Verdict::is_measurement()`); track its own rate as an instrument-health metric next to the
`timeout-indistinct` rate; and never let it reach a client bundle's inputs. What it deliberately
does not cover: whether the *echo server* was up. From the RU side a dead server, a wrong key and
a total block are the same silence, and the only host a sensor may probe is our own — so that case
is settled at analysis from the server's journal and from all sensors going quiet together, not by
a check on the sensor (see `deploy/run-battery.sh`).

Verdicts are **additive by minor version**: new verdicts may be appended; existing codes never
change meaning. A client seeing an unknown verdict in aggregated data treats it as
`timeout-indistinct` — which is exactly why a 0.1 consumer must not ingest 0.2 sensor data: it
would coerce `not-evaluated` back into the null verdict. Version-gate the reader before the run.

> **Reconcile against dpi-bench's property vocabulary.** This taxonomy and dpi-bench's per-strategy
> property vocabulary are mirror images: dpi-bench asserts what a *well-formed* split/seqovl/fake
> looks like at the byte level; a verdict here names what a *tampered* one looks like on the wire.
> Knowing the former sharpens the latter (esp. `payload-mutated` and `silent-drop-from-segment-N`).
> **First pull done (2026-09-04):** dpi-bench's third state — `exit 2 / mut?`, "I cannot judge this
> row" as distinct from pass and finding, which it grew after a rig-not-up run read as 29 findings —
> is `not-evaluated` above. Its byte-level *properties* were checked and do **not** transfer:
> they describe zapret2's own dissector, not the TSPU. Any future pull stays one-way, never a
> dependency that blocks either track; dpi-bench is a separate session and this file stays the
> source of truth for the wire-side taxonomy. How each verdict is *derived* from the
> sent-vs-arrived delta is specified in [ECHO.md](ECHO.md).

---

## Part 2 — Telemetry schema (#2 → #1)

Outcomes reported by sensors/clients. **k-anon to {ASN, region} or dropped. Aggregated at the
edge — the collector never receives a per-user row it could be compelled to de-anonymize.**

Conceptual record (pre-aggregation, never transmitted raw from a client):

```
{
  contract_version:  "0.2",
  asn:               uint32,          // operator ASN — coarse, no sub-prefix
  region:            string,          // coarse region code, not city/GPS
  transport:         enum,            // see the transport table below
  endpoint_class:    enum,            // which endpoint COHORT, never a specific endpoint id
  verdict:           enum,            // from Part 1
  metrics:           { rtt_ms?, rate_bps?, rst_ttl?, highest_marker?, ... },
  bucket_start:      uint64,          // coarse time bucket (see clock note), NOT a precise stamp
  sensor_class:      enum             // residential | vps | dark  (weights differ; see DESIGN)
}
```

### `transport` — the probe battery

Reconciled against amnezia-client `dev` on 2026-09-09. The wire name is normative; tree #2
implements from this column, so it is pinned per variant in `lok-contract` rather than derived
from the Rust identifier.

| wire name | amnezia-client | rides |
|---|---|---|
| `plain-tls-control` | — (Lokhotron's own control) | TCP |
| `wireguard` | `DockerContainer::WireGuard`, "WireGuard" | UDP |
| `amneziawg` | `DockerContainer::Awg` **and** `Awg2` — both `Proto::Awg` | UDP |
| `openvpn` | `DockerContainer::OpenVpn`, "OpenVPN" | UDP |
| `openvpn-over-cloak` | `DockerContainer::Cloak`, "OpenVPN over Cloak" | TCP |
| `xray-reality` | `DockerContainer::Xray` with `security=reality` | TCP |
| `shadowsocks` | `DockerContainer::SSXray`, "Shadowsocks" (AEAD `chacha20-ietf-poly1305`) | TCP |
| `ikev2` | `DockerContainer::Ipsec`, `Proto::Ikev2` | UDP |
| `synthetic-control` | — (Lokhotron's own control) | UDP |

**The axis is wire fingerprint, not amnezia-client's container inventory.** `Awg2` is a separate
container with its own installer and maps to the same `Proto::Awg`; one entry covers both. Add a
row when the TSPU could tell two things apart, not when Amnezia ships a container.

`wireguard`, `openvpn` and `ikev2` are *positive* controls: all three are cheap for a DPI to
recognise — amnezia-client's own copy says WireGuard is "easily identifiable by DPI systems due
to its distinctive packet signatures" — so a path that leaves them alone has said something as
definite as one that blocks them.

`rides` gates `Verdict::udp-class-drop`, which may only be reached from a UDP row. Calling a
class-level UDP drop on a TCP transport is a fabricated finding of exactly the kind the
calibration rig exists to catch.

Hard rules:
- **No user identifier, ever.** No device id, no install id, no precise timestamp, no GPS, no
  sub-ASN prefix. Any of these present → drop the report.
- **k threshold:** a {ASN, region, transport, bucket} cell is only emitted upstream once ≥ k
  independent sensors populate it. Below k, the edge holds or discards — it does not send.
- **Edge aggregation:** clients contribute to counts, not rows. The collector stores
  distributions, not events attributable to a reporter.
- **`sensor_class` weighting** lives in analysis, not here — residential > vps; `dark` is
  ground-truth only and never influences a bundle.
- **Clock:** `bucket_start` is coarse and derived from server-correlated time (5-tuple + payload
  nonce), not the in-country device clock. See DESIGN "clock correlation."

---

## Part 3 — Strategy-bundle format (#1 → #2)

The intelligence push. **A weighted distribution over surviving transports, not a single
winner** — argmax builds a monoculture (DESIGN, Correction 1). The client **samples** the mix.

```
{
  contract_version:  "0.2",
  issued_bucket:     uint64,          // coarse issue time
  ttl_buckets:       uint16,          // client stops trusting after this
  scope:             { asn: uint32, region: string },   // ONE slice per bundle
  mix: [                              // weighted; client samples, does not argmax
    { transport: enum, endpoint_class: enum, weight: float, min_floor?: float },
    ...
  ],
  signature:         bytes            // over the whole record; key pinned in client
}
```

Least-disclosure rules (this artifact reaches adversary hands):
- **One region slice per bundle.** A client for {ASN X, region Y} receives only that slice — never
  the global picture. Reading one bundle reveals one region's current mix, not the map.
- **`endpoint_class`, not endpoints.** The bundle names a *cohort* the client already knows how to
  resolve; it never enumerates concrete endpoints, and it **never** names a dark endpoint.
- **Weights, with an optional `min_floor`** so no single transport's share collapses to a
  fleet-wide tell even when one is clearly best. Diversity is deliberate.
- **Signed; unknown/failed signature → ignore.** Poisoning this channel redirects users to a
  monitored endpoint — signing is non-negotiable.
- **TTL'd** so a captured-and-replayed old bundle can't pin a fleet to a now-dead transport.

---

## Versioning & change policy

- `contract_version` is `major.minor`. **Minor** = additive (new verdicts, new optional fields);
  clients ignore unknown optional fields. **Major** = breaking; clients reject unknown major
  outright rather than guess.
- The spec is authored and bumped **here** (tree #1). #2 tracks it. A bundle or report whose
  version #2 doesn't implement is dropped, not best-effort-parsed.
- Keep this file the single source of truth for the boundary. If a field isn't here, it doesn't
  cross.

---

## Open before v1.0 (don't trust from memory — verify at build time)

- ~~The concrete transport enum~~ — **reconciled 2026-09-09** against amnezia-client `dev`
  (`containerEnum.h`, `protocolEnum.h`, `containerUtils.cpp`, `protocolConstants.h`). The draft
  guess named two transports the client cannot speak (`ss2022` — Amnezia's Shadowsocks cipher is
  `chacha20-ietf-poly1305`, and no `2022-blake3-*` exists in the tree; `obfs4` — that is Tor's,
  Amnezia uses Cloak) and treated REALITY as a transport when it is one of three security modes on
  the XRay container. Current set is the table above. Re-check when amnezia-client adds a container:
  add a variant only if the TSPU could tell it apart from an existing one — `Awg2` is a separate
  container that maps to `Proto::Awg` and needs no variant.
- k threshold value and the exact edge-aggregation mechanism (simple count vs. a real private
  aggregation scheme) need a threat-model pass before residential clients report anything.
- Signature scheme / key format should reuse whatever amnezia-client's config-update path already
  trusts, if it can carry bundles — don't invent a parallel PKI.
