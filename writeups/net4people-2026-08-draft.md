# DRAFT — not posted

> **Status: the live run has not happened.** Nothing is provisioned. Every number below comes
> either from the local calibration rig or from public OONI data; there is **no live RU measurement
> in this post**, and the sections marked *(pending)* are placeholders for the eventual update.
> Do not post a version that implies otherwise.
>
> **Decisions for the author before posting** — see the notes at the bottom: whether to name
> providers, and the fact that publishing is the layer that carries the actual Russian legal
> exposure (`deploy/LEGAL-RU.md`).

---

## Calibrating a censorship-measurement pipeline against injected ground truth, before trusting it on the wire

**TL;DR.** I built a measurement pipeline for characterising what Russia's TSPU does to a
connection — not pass/fail, but *what shape* the failure has — and calibrated it against
kernel-injected faults with known ground truth before pointing it at anything real. Eight fault
classes, eight correct verdicts, and three of them exist only to catch the pipeline inventing
findings — including one where a middlebox that swallows every packet could previously make the
tool report a clean path. Separately, a recruitment-free read on public OONI data says the
datacenter-vs-consumer gap in Russia is **provider-specific, not a constant**, which changes how a
VPS-based vantage can be interpreted at all. The live run is next. **I'm posting the method before
the run specifically to get it torn apart while that's still cheap.**

Code, data and the generated reports: <https://github.com/Mezo-oz/Lokhotron> (MIT).

### The problem this is trying to solve

Most censorship measurement answers "did it work?". For choosing a circumvention transport, that's
the wrong question — you want to know *how* it failed, because the shape implies the countermeasure.
A silent drop starting at segment 4 of a handshake, an injected RST with a TTL inconsistent with the
real peer, a throughput collapse after a successful handshake, and a total timeout are four
different diagnoses, and only the last one is uninformative.

So the primitive is a **delta**: what a sensor sent versus what a server I control received, joined
offline. The shape of the difference is the diagnosis. Verdict vocabulary is a closed set —
`ok`, `injected_rst_at_sni`, `silent_drop_from_segment{n}`, `throttle_to_rate{bps}`,
`udp_class_drop`, `payload_mutated`, `active_probe_observed`, `timeout_indistinct`.

`timeout_indistinct` is tracked as a first-class rate rather than swept aside. If most events land
there, the delta isn't informative and the central bet is wrong — which is a result I want in week
one, not month three.

### Why calibrate first

**On the live wire you cannot distinguish a capture bug from a finding.** If the classifier says
`injected_rst_at_sni` and you have never proven it can recognise one, you have a press release, not
a measurement. So before any live run: a two-namespace rig joined by a veth pair, with
`tc`/`nftables` injecting each fault class at known ground truth, asserting the pipeline recovers
the *injected* verdict.

| injected fault | mechanism | required verdict | result |
|---|---|---|---|
| clean path | none | `ok` | pass |
| drop from segment 4 | server-side drop of markers ≥ 4 | `silent_drop_from_segment{n:4}` | pass |
| rate limit to 128 kbit | `tc tbf` on the server's egress | `throttle_to_rate` | pass (measured ~124 kbit) |
| forged RST | `nft` mangles the RST's TTL to 200 | `injected_rst_at_sni` | pass (judged against a *measured* control TTL of ~64) |
| payload rewritten in flight | `nft @th,320,8 set` — kernel fixes the UDP checksum, as a real middlebox must | `payload_mutated` | pass |
| **foreign RST on another flow** | a second flow to a closed port emits RSTs with TTL mangled to 200 | **`ok` — must NOT fire** | pass |
| the probe's **own header** rewritten in flight | `nft @th,96,8 set` — the marker's high byte | `payload_mutated` — must NOT read as a drop | pass |
| **a reflector answers instead of the server** | the request bounced back byte for byte, unsigned | the drop verdict — **must NOT be `ok`** | pass |

The negative rows are the ones I'd argue matter most. A raw `AF_PACKET` capture sees every frame on the
interface, so on any shared vantage — which every rented VPS is: SSH, background traffic, a second
probe run — an unfiltered watch will eventually match some *other* flow's RST and judge its TTL
against a control measured on your route. That reads as `injected_rst_at_sni` on a healthy path: a
fabricated finding, and the worst thing this kind of tool can do.

I verified that this was a real defect and not a hypothetical, by running the same rig against the
pre-fix binaries in a detached worktree: they reported `injected_rst_at_sni` on a clean path, and
were silently blind to the payload rewrite. The fix is to scope every capture to the probe's own
5-tuple, which requires knowing your own ephemeral port *before* the capture opens — so the TCP
socket is bound before connect (no `std` API for that; it's a small `libc` shim).

The last two rows come from a second pass over the same question: *what else can this instrument be
made to say that isn't true?* Two things, both fixed by keying the echo protocol with a secret
shared between sensor and echo server.

The first was mine to have caught earlier. The probe's datagrams carried
`[nonce][marker][known payload]` with the payload a **public** function of the marker. Rewrite the
marker mid-path and the echo stops being recognisable, so the run reports a drop — I measured the
pre-fix binaries reporting `udp_class_drop`, i.e. *"UDP is dead on this path"*, against a path that
delivered all eight datagrams with one byte changed. The fix: derive the 32-byte payload as
`HMAC(K, nonce ‖ marker ‖ session)`, so it identifies the datagram *on its own*. A destroyed header
no longer destroys the evidence — the datagram is attributed by the payload it carries, and a header
rewrite reads as the mutation it is.

The second is worse, and it is the one I'd most like torn apart. With a public payload function,
*anything on the path can echo the probe's own datagram back* and be scored as an arrival. I put a
dumb verbatim reflector in the server's place: the pre-fix probe reported **`ok`** — a clean bill of
health for a path where the server received nothing. Any censor that swallows traffic and reflects
the probe gets to choose what my instrument reports. The fix is domain separation: the request tag
and the response tag are different HMACs, so an arrival means *the far end signed it*, and a
middlebox can replay a request but cannot turn one into a response without the key. An echo that is
attributable but unsigned is counted and never scored as delivery.

Keying bought two things I didn't design for and will take. The server now answers only
authenticated datagrams, which means it is not an open UDP reflector on a public IP — on a rented
box that is an abuse report and a null-route away from looking exactly like a censorship finding.
And because the server signs *what it received* rather than what it should have, whichever of the
four (header, payload) × (as-sent, as-received) tag combinations verifies tells you **which leg**
each rewrite happened on. Directional mangling falls out for free.

It costs something honest, too. A sensor whose key doesn't match the server's receives nothing, and
that is indistinguishable from a total block — so provisioning ends in a pre-flight run that refuses
to start the timer unless it comes back `ok`. And there is a residual blind spot I'd rather name
than bury: a *forward-leg* rewrite of the 20 bytes that authenticate the run still reads as a drop,
because the server discards the datagram unanswered. That is a deliberate trade against being a
reflector, not an oversight.

Remaining limits, stated rather than discovered later: the capture path is IPv4-only today, and
everything above is lab ground truth — kernel-injected faults on a veth pair, not a censor.

### A recruitment-free read on the datacenter-vs-consumer gap

The obvious cheap vantage is a Russian VPS. But TSPU is deployed at the operator, and Russian
datacenter ASNs may sit behind different equipment, or none — so a VPS may be measuring *a different
device*, not a lenient version of the same one. That's not a caveat, it decides what a VPS-based
result can claim.

Rather than recruit anyone, I split OONI's existing Russian coverage for circumvention-tool
reachability by reporting ASN — consumer operators vs hosting/DC providers — and compared block
rates. 30-day window, block rate = `anomaly / (anomaly + ok)` with OONI failures excluded from the
denominator (a test that couldn't run isn't evidence of blocking), 95% Wilson intervals:

| test | consumer ISP | hosting/DC | gap |
|---|---|---|---|
| `psiphon` | 74.8% (n=49,430) | 9.8% (n=1,097) | **+65.0 pp** |
| `tor` | 99.3% (n=29,963) | 92.6% (n=1,047) | +6.7 pp |
| `telegram` | 85.8% (n=30,148) | 93.7% (n=1,034) | **−7.9 pp** |

**"Datacenter paths are more lenient" is false as a general statement.** It is strongly true for
Psiphon, marginal for Tor, and *reversed* for Telegram.

And the pooled numbers are the least interesting cut. Within the hosting bucket, same country, same
month, same test, block rates spread **87–96 pp** between providers — one RU hosting provider sits
near-clean across Tor/Psiphon/Telegram while consumer operators are at 75–99%. Consumer operators
don't spread like that; they cluster.

The practical consequence: **which RU provider you rent decides what you can measure.** Renting on
price alone is choosing your findings at random. Extending the screen to 22 providers I might
actually rent, 13 have no OONI coverage at all — so for most providers you cannot preview this, and
the answer is to diversify vantages rather than optimise one.

Where this read is weak, since it's easy to over-read: these are tool-reachability tests, not the
protocol-handshake shaping the pipeline measures, so it's directional evidence about the *vantage*.
OONI probes on hosting ASNs are few and self-selected. For `tor` specifically the gap is confounded
— the unclassified tail (93 ASNs, n=12,403) sits at 92.4%, indistinguishable from the DC bucket, so
that split may be tracking operator size rather than DC-vs-consumer. For `psiphon` the tail lands at
74.2% against the consumer bucket's 74.8%, which is what a clean split should look like. ASNs were
bucketed on identity evidence only — holder name, website, what the company sells — never on
measured rate, with unresolved ones left unclassified and reported with their own rate.

### What is not in this post

**(pending) The live run.** One non-RU echo server plus 2–3 RU sensors at different providers,
running the battery for a week. The honest claim will be scoped to *those providers'* datacenter
paths, plus the OONI comparison as the directional gap read — not a consumer result.

**(pending) Per-verdict results, `timeout_indistinct` rate, and the cross-provider comparison**,
which is the interesting one: divergence between providers would be the DC-vs-consumer finding
measured on my own instrument instead of inferred from OONI.

I'm **not recruiting sensor operators in Russia**, and won't. A VPS under my own name is a risk I
can assess and accept; a volunteer's device is a risk I'd be transferring to someone else, and the
legal environment is not static. The residential signal, if it ever comes, comes from opt-in
client-side telemetry that is k-anonymous and aggregated at the edge so the collector cannot
de-anonymise it even under coercion — designed now, shipped last, and never from anyone who didn't
install it deliberately.

### Reproducing

```sh
sudo rig/netns-test.sh          # 49 tests, run inside a private netns
sudo rig/netns-calibrate.sh     # the eight calibration cases, needs netns + nftables
python phase0/ooni_gap.py       # the gap read (stdlib only, live OONI + RIPEstat)
python phase0/provider_screen.py
```

### What I'd like torn apart

1. **The TTL-anomaly test for injected RSTs.** I judge an observed RST against a control TTL
   measured on the same route, threshold ±5. What breaks that in the wild — ECMP with
   different-length paths, middleboxes that clone the peer's TTL, anything else?
2. **The verdict vocabulary.** Is the closed set missing a shape that matters? I'd rather add it
   before the schema is versioned than after.
3. **Is the DC-vs-consumer split even recoverable from OONI's ASN metadata?** My classification is
   name-based and I don't love it. Is there a better public signal for "this ASN is an eyeball
   network"? (CAIDA's AS-classification dataset used to be the obvious answer; its public path 404s
   now.)
4. **The `torsf`/`riseupvpn` coverage is too thin to use.** Is there a better tool-reachability
   proxy for VPN-protocol shaping in the OONI corpus?
5. **Anything that makes `timeout_indistinct` less likely to dominate** the live run.
6. **The keyed echo scheme, and mostly what it still can't see.** 64-bit HMAC-SHA-256 tags, domain
   separated by leg, with the per-marker payload doubling as the identifier. The known gap: a
   forward-leg rewrite of the run authenticator still reads as a drop, because the server won't
   answer it — the alternative was an open UDP reflector on a public IP. Is that the right side of
   that trade? And is there a class of on-path behaviour that still gets to choose what this
   instrument reports?

---

## Notes for the author — remove before posting

- **Results are pending, not omitted.** If the run hasn't happened when you post, keep the framing
  as "method up for critique". Don't let the calibration table read as live findings.
- **Naming providers.** The draft describes the near-clean provider without naming it, but
  `phase0/PROVIDER-SHORTLIST.md` names it and the tool regenerates it in one command, so this is
  presentation, not protection. Argument for naming: reproducibility, and the OONI data is already
  public. Argument against: a public post that highlights "this provider looks unfiltered"
  plausibly gets it filtered, which costs the people currently relying on it. Your call — but make
  it deliberately.
- **Publishing is the exposure layer.** Per `deploy/LEGAL-RU.md`, the sensing side's Russian legal
  exposure is low; the *publishing* side is what the March 2024 dissemination ban targets, and
  research organisations have been designated for less. This post is that layer.
- **Check the name invariant** if any part of this is ever reused in a client-facing artifact.
