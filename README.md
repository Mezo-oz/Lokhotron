# Lokhotron

Collects and measures data from the TSPU.

A distributed measurement system that continuously learns **what the TSPU is doing right now,
per operator and region**, and turns that into signed "use this transport here" intelligence
that clients inside Russia consume to heal themselves. You can't see the censor's box — but you
can see **what it did**, by diffing what a sensor sent against what a server you control
received. The *shape* of that difference is a diagnosis, not just pass/fail.

This is the **sensing layer** — your infrastructure (Linux VPSes, in and out of Russia). It is
deliberately **not** the client that ships to phones: that's a separate tree, so the code on an
adversary-controlled device can't contain what this layer knows (endpoint inventory, dark
canaries, control-plane logic, other regions' data). See [DESIGN.md](DESIGN.md) → "The three
trees."

## Docs

- **[DESIGN.md](DESIGN.md)** — architecture, the repo-split security boundary, the corrections
  the concept went through (targeting-oracle / monoculture, the narrow dpi-bench inheritance, the
  DC-vs-consumer gap), and phasing.
- **[CONTRACT.md](CONTRACT.md)** — the versioned spec that crosses the boundary to the client:
  verdict vocabulary, telemetry schema (k-anon), signed strategy-bundle format.
- **[ECHO.md](ECHO.md)** — the sequence-marked echo protocol: the two-capture-point delta, markers
  without a fingerprint, verdict derivation, and the Phase 1 step-0 fault-injection calibration
  harness (the ground-truth net that replaces "do dpi-bench first").
- **[STATUS.md](STATUS.md)** — living sitrep: phase status, locked decisions, next actions.
- **[phase0/](phase0/)** — the DC-vs-consumer gap read: does a datacenter vantage tell you anything
  about the consumer path? Recruitment-free, built on OONI's existing RU coverage.

## Status

**Phase 1 step 0 is built and verified on real packets** — the probe battery, the AF_PACKET
capture and the verdict classifier are calibrated against kernel-injected faults in a netns rig
(8/8 cases, three of them negative: another flow's RST cannot contaminate a verdict, a rewrite of
the probe's own header is not reported as a drop, and a reflector cannot make a dead path read
healthy).
The provisioning scripts exist; no hosts are rented yet. **Phase 0's gap read is done**
([phase0/](phase0/)) and it changed the provisioning plan: block rates spread 87-96 pp *between RU
hosting providers*, so which provider you rent decides what you can measure.

Next is Phase 1 proper: one non-RU reverse-measurement server + a couple of RU VPS sensors running
the battery live, producing a segment-granularity delta ("what the TSPU did to an AmneziaWG
handshake in operator X today"). That artifact is publishable on its own; every downstream phase is
justified by what Phase 1 actually finds. See [STATUS.md](STATUS.md) for the live picture.

## Related trees

- `dpi-bench` (`X:\DPI-Tester`) — the offline zapret2 harness; teaches the capture/diff primitive
  on a lab target.
- The client (tree #2) — likely contributed upstream to **amnezia-client** rather than a repo of
  its own, to inherit its trust anchor. Design notes: `X:\Lokhotron-client\`.

## License

MIT — see [LICENSE](LICENSE). Matches dpi-bench, same world.
