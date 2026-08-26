# Lokhotron — the contract (v0.1 draft)

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
| `timeout-indistinct` | died with no distinguishing shape | either | the null verdict — see note |

**`timeout-indistinct` is the honest failure mode.** If most blocks land here, the delta isn't
informative and the thesis is in trouble — that's the thing Phase 1 exists to find out in week
one. Track its rate as a first-class metric.

Verdicts are **additive by minor version**: new verdicts may be appended; existing codes never
change meaning. A client seeing an unknown verdict in aggregated data treats it as
`timeout-indistinct`.

---

## Part 2 — Telemetry schema (#2 → #1)

Outcomes reported by sensors/clients. **k-anon to {ASN, region} or dropped. Aggregated at the
edge — the collector never receives a per-user row it could be compelled to de-anonymize.**

Conceptual record (pre-aggregation, never transmitted raw from a client):

```
{
  contract_version:  "0.1",
  asn:               uint32,          // operator ASN — coarse, no sub-prefix
  region:            string,          // coarse region code, not city/GPS
  transport:         enum,            // amneziawg | vless-reality | ss2022 | obfs4 | plain-tls-control
  endpoint_class:    enum,            // which endpoint COHORT, never a specific endpoint id
  verdict:           enum,            // from Part 1
  metrics:           { rtt_ms?, rate_bps?, rst_ttl?, highest_marker?, ... },
  bucket_start:      uint64,          // coarse time bucket (see clock note), NOT a precise stamp
  sensor_class:      enum             // residential | vps | dark  (weights differ; see DESIGN)
}
```

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
  contract_version:  "0.1",
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

- The concrete transport enum will change as the client's supported transports settle — keep it in
  lockstep with amnezia-client's actual transport set, not this draft's guess.
- k threshold value and the exact edge-aggregation mechanism (simple count vs. a real private
  aggregation scheme) need a threat-model pass before residential clients report anything.
- Signature scheme / key format should reuse whatever amnezia-client's config-update path already
  trusts, if it can carry bundles — don't invent a parallel PKI.
