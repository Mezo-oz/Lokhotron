# phase0 — the DC-vs-consumer gap read

Phase 0 is deliberately narrow. DESIGN.md gives it exactly one job: use OONI's existing Russian
coverage to get a **recruitment-free** read on whether a datacenter vantage tells you anything
about the consumer path, because DESIGN.md Correction 3 — the claim that a cheap RU VPS may sit
behind a different TSPU box, or none — is load-bearing for how much a VPS-only Phase 1 may
conclude. Anything beyond that job is a dashboard, and a dashboard is procrastination.

**Latest read: [FINDINGS-2026-08-27.md](FINDINGS-2026-08-27.md).** Short version: the gap is real
but **provider-specific** (87–96 pp spread *within* the hosting bucket) and its sign flips by test.
Provider choice for the RU sensor is therefore a measurement decision, not a procurement one.

## Running it

```sh
python phase0/ooni_gap.py                       # last 30 days, RU, default test set
python phase0/ooni_gap.py --since 2026-07-28 --until 2026-08-27 \
    --out-md phase0/gap-2026-08-27.md --out-json phase0/gap-2026-08-27.json
```

Stdlib only — no pip install, runs on a bare sensor box. Two live sources:
`api.ooni.io/api/v1/aggregation` (measurements, `axis_x=probe_asn`) and RIPEstat `as-names` (holder
names, bulk, cached in `cache/asn_names.json` so a re-run costs one API call per test).

Once the RU VPS exists, `--dc-measurements FILE` swaps our own probe results in for the OONI
hosting side — the comparison DESIGN.md actually asks for ("run the same reachability checks from
your DC VPS and diff them"). Format: `{"psiphon": {"anomaly": 12, "ok": 88}, ...}`.

## Method, and why it is shaped this way

- **Block rate = `anomaly / (anomaly + ok)`.** OONI *failures* are excluded from the denominator: a
  test that could not run is not evidence of blocking. `vanilla_tor` is excluded from the default
  test set for this reason — ~95% of its RU measurements are failures, so its rate describes the
  test rather than the path.
- **95% Wilson intervals everywhere**, because the two sides differ in size by ~50×. A 25-
  measurement bucket must not read like a 30,000-measurement one.
- **ASNs are classified on identity evidence only** — RIPE holder name, website, what the company
  sells. Never on the measured rate. Bucketing after looking at rates is how you manufacture a gap.
  Rules and per-ASN evidence live in `asn_classes.json`, including a `deliberately_unclassified`
  section for identities that could not be resolved.
- **The unclassified tail is reported with its own block rate**, not dropped. If the tail's rate
  sits on the consumer bucket's, the classification did not create the gap; if it sits on the DC
  bucket's, the gap for that test is suspect. Both happen in the current data, and the finding says
  which is which.
- **Per-ASN detail on the DC side.** The hosting bucket is small and wildly heterogeneous, and
  pooling it hides precisely what Correction 3 is about.

## Classification is not procurement clearance

This tool answers "is this ASN a datacenter vantage?" It does **not** answer "may we lawfully buy
from them?" Those come apart: OFAC designated the Russian hoster **Aeza Group** in July 2025, and
`aeza` sits in this directory's hosting keyword list — the classifier would happily call it a good
DC vantage. For a US-operated project, transacting with an SDN is strict liability. Screen any
provider you intend to *rent* against the OFAC SDN list first; see
[deploy/LEGAL-RU.md](../deploy/LEGAL-RU.md).

## What it cannot say

These are tool/endpoint reachability tests, not the VPN-protocol handshake shaping Lokhotron
measures — directional evidence about the *vantage*, not a prediction of the battery's findings.
OONI probes on hosting ASNs are few and self-selected. `anomaly` is OONI's heuristic, not a
confirmed block. And a gap here supports Correction 3 while its absence would not refute it: these
are two populations measured by the same test, not one measurement from two vantages.
