# Lokhotron — the sequence-marked echo protocol

The core of Phase 1. Turns *"the transport broke"* into *"the TSPU did action Y, at segment
granularity."* This is dpi-bench's differential primitive aimed at the live adversary: capture
what a sensor **sent**, capture what a server you control **received**, and the difference — plus
timing and RST metadata — classifies into a [verdict](CONTRACT.md#part-1--verdict-vocabulary).

The reassembler from dpi-bench does **not** appear here (Correction 2): on the live wire the
server is a real endpoint, so the delta is a direct sent-vs-arrived comparison, not an
endpoint-model simulation. What's new code: the probe, the AF_PACKET capture on both ends, the
verdict classifier, and the calibration harness that proves all three before you trust a live run.

---

## 1. The two capture points ARE the measurement

```
  [ probe / sensor in RU ]                              [ echo server, non-RU, yours ]
    emits marked traffic                                  accepts it
    AF_PACKET tap: what LEFT ───── censored path ─────►   AF_PACKET tap: what ARRIVED
    records inbound RSTs (TTL/IP-ID), timing               logs per session, best-effort acks
             │                                                       │
             └──────────── joined offline by session key ───────────┘
                                    = the delta
```

- **Sensor-side tap** (AF_PACKET, below the socket): the ground truth of what the sensor put on
  the wire, plus any **inbound RST** with its IP TTL and IP-ID (the injected-vs-endpoint tell).
- **Server-side tap** (AF_PACKET, below the stack): the ground truth of what the TSPU *delivered*
  — before the kernel normalizes or ACKs anything.
- **The delta** = server-arrived compared against sensor-sent, joined by session key. Everything
  else (verdict, metrics) is derived from that join.

Capturing below the socket on both ends is deliberate: a socket-level "I sent N bytes" hides
retransmits, RSTs, and mid-flight mutation. The censor operates on packets, so you measure packets.

---

## 2. Markers without a fingerprint: use the transport's own structure

Tension: to measure *"what the TSPU does to a real AmneziaWG handshake,"* the bytes on the wire
must **be** a real handshake — you cannot prepend a probe magic to them without (a) changing what
the censor inspects and (b) handing the TSPU a trivial fingerprint. So the marker cannot live in
the inspected content for real-transport probes.

Resolution — **the marker is the transport's own sequence structure, recovered from the capture:**

- **TCP transports** (Reality, SS2022-over-TCP, plain-TLS control): the sensor controls
  segmentation and emits the payload as N segments of known sizes. **TCP sequence numbers are the
  markers.** The delta compares the set of `(seq_range, payload_hash)` tuples emitted against those
  received. Absent range → drop. Hash mismatch on a matching range → mutation. All of it is
  ordinary TCP; nothing on the wire says "probe."
- **UDP transports** (AmneziaWG): the sensor controls datagram count and sizes; **datagram index +
  length is the marker.** Server sees which datagrams arrived.
- **Session join key** (to correlate the two logs without trusting clocks):
  - *Real-transport probes* — use the transport's own session identifier, which the server sees
    anyway: WireGuard sender index, TLS `ClientHello.random`, etc. No added bytes.
  - *Synthetic control probe* — an openly-synthetic stream that IS allowed a header, because its
    whole job is to be a clean, fully-labeled baseline. It is never dressed as a real transport, so
    its fingerprint doesn't matter — which is what lets the header carry authentication a
    real-transport probe could not. **This is the keyed format specified in §2a**, implemented in
    the `lok-wire` crate.
  - Fallback within a capture window: the 4-tuple, corrected for NAT on the src side.

**No app-layer marker rides inside real-transport payloads.** The synthetic probe carries the
explicit header; the real ones are read purely from packet structure.

---

## 2a. The keyed synthetic probe (v2)

The first cut of the synthetic probe was `[u32 nonce][u32 marker][32 bytes of known payload]`,
echoed verbatim, with the payload a *public* function of the marker. Two failure modes only show
up against a live adversary, and both produce a **wrong verdict**, not a missing one:

1. **A rewritten header read as a drop.** Rewrite the marker and the echo stops being recognizable;
   the run reports `silent-drop-from-segment` (in a UDP battery, `udp-class-drop`) on a path that
   delivered every datagram. A fabricated block.
2. **Delivery could be faked.** Anything on the path could echo the datagram back itself and the
   probe scored it as arrived. A censor that swallows traffic and reflects the probe reads as `ok`
   — the fleet is then told a dead path is the healthy one.

Both close with one mechanism: **a shared secret between sensor and echo server**, `LOK_PROBE_KEY`,
64 hex characters, provisioned out of band. All tags are HMAC-SHA-256, truncated to 64 bits, with a
domain string per field. 64 bytes, big-endian:

```text
 off  0  u32   nonce         run kind: probe | ttl-calibration
 off  4  u32   marker        datagram index within the run
 off  8  u64   session       random per run; kills cross-run replay
 off 16  u64   session_tag   HMAC(K, "lok/sess/v2" || nonce || session)
 off 24  u64   leg_tag       request:  HMAC(K, "lok/req/v2"  || header || payload)
                             response: HMAC(K, "lok/resp/v2" || header || payload)
 off 32  [32]  payload       HMAC(K, "lok/pay/v2" || header)
```

Three properties do the work:

- **The payload is a keyed function of the header**, so it identifies the datagram *on its own*.
  When a header is rewritten in flight, the datagram is still attributed — to the marker whose
  payload it carries (exact match, or nearest within 8 of 32 bytes and unique; a tie is not
  evidence). Hole 1 becomes `payload-mutated`, which is what it always was.
- **The leg tag is domain-separated between request and response**, so an arrival means *the far
  end signed it*. A middlebox can replay a request; it cannot turn one into a response without K.
  Hole 2 becomes the drop it is. An echo that is attributable but unsigned is counted
  (`unauthenticated`) and **never** scored as an arrival: an unauthenticated echo is not evidence
  of delivery, by construction.
- **The server signs what it received, not what it should have.** So whichever of the four
  (header, payload) × (as-sent, as-received) combinations verifies tells you *which leg* each
  rewrite happened on. Directional mangling is a real finding and comes out for free.

`session_tag` deliberately covers only the nonce and session — not the marker, not the payload.
That is what lets the server **admit only authenticated runs** (an unauthenticated open UDP echo on
a public IP is a reflector, and the resulting abuse report is one provider null-route away from
looking exactly like a censorship finding) while still echoing datagrams whose marker or payload
were rewritten, which is the evidence hole 1 needs.

**Residual blind spot, stated plainly:** a *forward-leg* rewrite of the 20 bytes that authenticate
the run — nonce, session, session tag — makes the server discard the datagram, and it still reads
as a drop. That is a deliberate trade against running an open reflector. Every other byte is
echoed and its rewrite detected.

**And the operational cost:** a sensor whose key does not match the server's receives nothing, so
every verdict it produces reads as a total block. That is why `deploy/sensor-setup.sh` ends in a
pre-flight run and refuses to enable the timer unless it comes back `ok`.

---

## 3. Clock-free correlation

Absolute clocks in-country aren't trustworthy and NTP may itself be shaped. The sensor and server
logs join on **`{session_key, marker}`**, and *relative* timing within each capture is what feeds
throttle/timing verdicts — never a cross-host absolute-time subtraction. Coarse wall-time is
recorded only for bucketing into the [telemetry schema](CONTRACT.md#part-2--telemetry-schema-2-1),
never for delta math.

---

## 4. The probe battery

Each probe is one transport driven to a known endpoint, capture running both ends. Run the battery
**gently** — spread out, low-rate, cover-consistent (a burst of odd parallel connections is itself
flaggable in 2026).

| probe | payload on wire | primary verdicts it can produce |
|---|---|---|
| `plain-tls-control` | real TLS ClientHello, benign SNI | baseline; `ok` establishes the path is up |
| `reality` | VLESS+Reality handshake to a real cover host | `injected-rst-at-sni`, `active-probe-observed`, drop/mutate |
| `amneziawg` | real WG handshake initiation (UDP) | `udp-class-drop`, drop, `timeout-indistinct` |
| `ss2022` | Shadowsocks-2022 handshake | drop, mutate, `throttle-to-rate-R` |
| `obfs4` | obfs4 handshake | drop, mutate |
| `synthetic-control` | labeled probe header + payload | ground-truth marker recovery; segment-drop resolution |

The **control pair matters**: `plain-tls-control` up while `amneziawg` dies on the same path,
same window, is what upgrades "WG failed" into `udp-class-drop` rather than "the path is down."

### Bulk phase for throttling

After a handshake reaches `ok`, a probe may enter a short **bulk phase**: send a known volume,
measure server-side arrival rate over time. `throttle-to-rate-R` fires when the handshake completed
but sustained arrival rate sits far below both sent rate and the control's rate.

---

## 5. Verdict derivation (delta → CONTRACT Part 1)

The classifier is a pure function of the joined delta. Deterministic mapping:

| observation in the joined delta | verdict |
|---|---|
| all emitted ranges/datagrams arrive **signed by the far end**, hashes match, handshake completes | `ok` |
| inbound RST at sensor shortly after SNI; **RST TTL/IP-ID inconsistent** with the real peer; server logged no RST | `injected-rst-at-sni` |
| server received contiguous markers up to N-1, nothing after; sensor kept sending | `silent-drop-from-segment-N` |
| matching `seq_range` arrives but `payload_hash` differs | `payload-mutated` |
| a datagram is recovered by its keyed payload but its **header** was rewritten in flight (§2a) | `payload-mutated` — *not* a drop |
| echoes arrive but none carry the far end's signature (reflected or forged) | the drop verdict the shape implies, plus the integrity counters |
| handshake `ok`, bulk-phase arrival rate ≪ sent and ≪ control | `throttle-to-rate-R` |
| UDP probe yields no arrivals while TCP control on same path/window is `ok` | `udp-class-drop` |
| (server-side) a Reality probe was forwarded to the real cover site | `active-probe-observed` |
| died with none of the above distinguishing shapes | `timeout-indistinct` |

**`injected-rst-at-sni` self-identifies.** A middlebox forging a RST rarely matches the real peer's
IP TTL and IP-ID sequence. The sensor captures the RST's TTL/IP-ID; the control probe establishes
the *legitimate* peer's values; a mismatch plus "server never sent a RST" is the injection
signature. This one needs no server round-trip beyond confirming absence.

**`timeout-indistinct` is tracked as a first-class rate, not swept aside.** If most blocks land
here, the delta isn't informative and the central bet is in question — which is exactly the thing
Phase 1 exists to surface in week one.

---

## 6. Reporting / back-channel

The server *logs*; it does not depend on telling the sensor inline. Best-effort acks may ride back
while a path is open, but the authoritative join happens **offline** from the two logs by session
key. This is deliberate: the report channel is itself censored traffic (store-and-forward, buffer
when blocked — see DESIGN), so the design never assumes the sensor learns its own result in real
time. The *return* of buffered reports after a blackout is itself signal.

---

## 7. Phase 1 step 0 — calibration harness (build this FIRST)

**On the live wire you cannot distinguish a capture bug from a finding.** So before any live run,
prove the pipeline against **known ground truth** locally. This is dpi-bench's discipline applied
to Lokhotron's own code — and it's the real answer to "do dpi-bench first," at a fraction of the
cost.

A netns/loopback rig with two namespaces (sensor, server) and a middlebox point between them that
**self-injects each verdict** on demand:

| injected condition | mechanism | classifier MUST output |
|---|---|---|
| segment N dropped | `nftables`/`tc` drop matching the Nth segment / byte offset | `silent-drop-from-segment-N` |
| forged RST after SNI | NFQUEUE helper watches for the SNI, injects a spoofed RST with a **distinct TTL** | `injected-rst-at-sni` |
| payload rewrite in flight | `nftables` raw-payload set (`@th,320,8`) on the server's egress — the kernel fixes the UDP checksum, as a real middlebox must | `payload-mutated` |
| **the probe's own header rewritten** in flight | `nftables` raw-payload set (`@th,96,8`) — the marker's high byte | `payload-mutated` — *not* a drop (§2a hole 1) |
| **a reflector answers instead of the server** (negative case) | `echo-server ... reflect`: the request bounced back byte for byte, unsigned | the drop verdict — *not* `ok` (§2a hole 2) |
| rate limit to R | `tc tbf`/`htb` on the middlebox link | `throttle-to-rate-R` |
| UDP dropped, TCP kept | `nftables` drop udp / accept tcp | `udp-class-drop` |
| clean path | no injection | `ok` |
| **foreign RST on another flow** (negative case) | a second flow to a closed port answers with RSTs whose TTL is mangled to 200 | `ok` — *not* `injected-rst-at-sni` |

Calibration passes when the probe + AF_PACKET capture + classifier recover the **injected** verdict
for every row, with no false positives on the clean path. Only then does the calibrated probe point
at the live RU/non-RU VPS pair. The harness doubles as the regression suite: every new verdict added
to CONTRACT Part 1 gets an injection recipe here before it's trusted in the field.

The forged-RST injector deliberately uses a TTL/IP-ID *unlike* the loopback peer, so the
self-identification logic in §5 is exercised, not bypassed.

**Every case here must be a real regression, not decoration.** Before a case is added, the
pre-change binaries are run against the same injected fault in a detached worktree, and the wrong
verdict they produce is recorded. A case that passes on both sides of the change proves nothing.

**Run the suite where loopback works.** `rig/netns-test.sh` runs the whole `cargo test` workspace
inside a private network namespace. The loopback cases are the ones that prove the probe and the
classifier agree on ground truth, so they must not be the ones skipped when the host's loopback is
unusable — some WSL networking modes swallow IPv4 loopback UDP specifically (TCP to `127.0.0.1`
works, `::1` works, UDP to `127.0.0.1` vanishes), which fails every UDP case for a reason that has
nothing to do with the code.

**The negative cases are not optional.** A raw `AF_PACKET` capture sees every frame on the
interface, so on any shared vantage — which every real VPS is: SSH, background updates, a second
probe run — an unfiltered watch will eventually match some *other* flow's RST and judge its TTL
against a control measured on our route. That reads as `injected-rst-at-sni` on a healthy path:
a fabricated finding, the worst failure this project can ship. Every capture is therefore scoped
to the 5-tuple of a socket the probe bound *before* opening the capture, and the rig proves the
scoping on the wire rather than only in unit tests.

---

## 8. Open questions (verify before hardening)

- **Segment-drop resolution vs. retransmission.** TCP retransmits; the classifier must not read a
  retransmit as a second arrival or a drop-then-recover as `ok`. Model the retransmit explicitly in
  the delta before trusting `silent-drop-from-segment-N` live.
- **NAT and the 4-tuple fallback.** Confirm the session-key join survives carrier-grade NAT on the
  RU side; lean on transport session identifiers over the 4-tuple wherever both exist.
- **Gentleness budget.** Define the concrete rate/spacing that keeps the battery under the "odd
  parallel probes" detection pattern — this is a safety parameter, not a performance knob.
- **AF_PACKET privileges on cheap VPSes.** Confirm `CAP_NET_RAW`/`CAP_NET_ADMIN` are available on
  the target VPS images before committing to below-socket capture there (a container VPS may not
  grant them) — the "missing capability looks like an incompatibility" trap.
- **Reconcile the verdict set with dpi-bench's property vocabulary** once that firms up (one-way
  pull; see CONTRACT Part 1).
