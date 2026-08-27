# Provider shortlist for the RU sensor (screened 2026-08-27)

Human conclusions from [`PROVIDER-SCREEN-2026-08-27.md`](PROVIDER-SCREEN-2026-08-27.md) (generated
data; re-run `python phase0/provider_screen.py`). Read
[`../deploy/LEGAL-RU.md`](../deploy/LEGAL-RU.md) first — this ranks vantages, it does not clear
anyone to be paid.

## Sanctions screen: one exclusion

**Aeza — do not transact.** AEZA GROUP LLC, AEZA INTERNATIONAL LTD and AEZA LOGISTIC LLC are all on
the SDN list (designated 2025-07-01). This is also the control case: it is in `providers.json`
precisely so that a screen returning zero hits is recognisable as broken rather than clean.

Every other entity match was a generic-token collision and was cleared by hand — `first` from FIRST
SERVER LIMITED, `guard` from DDoS-Guard, `astra` from ASTRA CLOUD, `ekspert` from Mediasoft ekspert,
plus person-name collisions on `Ihor`, a common Ukrainian given name. Those verdicts are recorded in
`providers.json` under `screen_review`, so if a future run produces *more* hits than were reviewed,
it shows up instead of blending in.

## What the OONI data can tell you before you pay

**13 of 22 candidates have no OONI coverage at all.** You cannot preview them. That is the single
most useful output here, and it is the argument for diversifying rather than optimising: for most
providers, renting is the only way to find out.

For the nine with coverage, four distinct path profiles appear. Consumer baseline for comparison
(from the gap read): `psiphon` 74.8%, `tor` 99.3%, `telegram` 85.8%.

| profile | providers | `psiphon` | `tor` | `telegram` | reading |
|---|---|---:|---:|---:|---|
| **A. Consumer-like** | MTW | 79.1% (n=325) | 90.9% (n=11) | 80.0% (n=10) | the only candidate whose Psiphon rate is statistically indistinguishable from consumer networks |
| **B. Protocol-selective** | Timeweb, Cloud.ru, IHOR, FirstByte | 0.3–7.4% | 80–99.5% | 98–100% | Tor and Telegram filtered like a consumer path; Psiphon essentially untouched |
| **C. Partial** | Selectel, Yandex Cloud | 5–6% | 57–60% | 51–64% | a distinct middle profile, but small n (20–63) |
| **D. Near-clean** | Beget | 3.7% (n=27) | 16.0% (n=25) | 7.4% (n=27) | little or no filtering visible on any test |

Beget's profile is the interesting one: wide intervals on its own, but it reproduces the 30-day gap
read (13.0 / 4.0 / 0.0%) in an independent 90-day window. Two windows agreeing is worth more than
either alone.

## Recommendation: rent three, chosen to span profiles

The Phase 0 finding was that DC paths differ by provider, so buying three samples of the *same*
profile learns little. Spanning them turns the provider choice into an experiment:

1. **MTW** (AS48347) — profile A. Best chance of a DC path that behaves like a consumer one. Only
   its Psiphon figure is well-sampled; treat the rest as unmeasured.
2. **Timeweb** (AS9123) — profile B, and the best-characterised candidate before purchase
   (n≈1,600/test). A mainstream provider, so also the most reproducible for anyone reading the
   write-up.
3. **Beget** (AS198610) — profile D, as the near-clean control. If our battery also sees nothing
   there, that is Correction 3's "a different box, or none" confirmed on our own instrument rather
   than inferred from OONI — which is a publishable result in itself.

Selectel is the natural substitute if you want a large, well-known provider in the middle profile,
at the cost of thinner data (n≈55).

## Caveats that matter at purchase time

- **The ASN with signal may not be the ASN you land in.** FirstByte's numbers are almost entirely
  AS205090 (n=2,102) while its other ASNs carry n=1; Timeweb's are AS9123, not TimewebCloud
  (AS51789, n=8). A plan can land in a different ASN than the one measured. **After renting, check
  the assigned IP's real ASN** and put that in `lokhotron-sensor.env` — do not assume.
- These are other people's OONI probes measuring **tool reachability**, not our battery measuring
  protocol shaping. Use them to choose *diverse* vantages, not to predict our verdicts.
- Small samples are marked. MTW's `tor`/`telegram` (n=10–11) and Yandex Cloud's (n=20–22) are
  directional at best.
- **A "no match" sanctions result is not clearance**, and this screen only covers OFAC. It says
  nothing about EU/UK lists, export controls, or whether a payment rail is lawful.
- Re-run before buying. Designations and filtering both change month to month.
