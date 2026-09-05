//! The versioned boundary contract, as Rust types.
//!
//! This is the ONLY thing that crosses the #1 (Lokhotron) <-> #2 (client) boundary.
//! It is a *spec*, encoded here for #1's own use. The client (amnezia-client upstream)
//! **reimplements** these shapes and must **not** take a dependency on this crate — that
//! is what keeps #1's internals (endpoint inventory, dark canaries, control-plane logic)
//! out of an artifact that ships to adversary-controlled phones.
//!
//! See `CONTRACT.md` for the authoritative prose and versioning policy.

use serde::{Deserialize, Serialize};

/// Contract version stamped on every crossing artifact. `major.minor`; unknown major
/// is rejected by the client rather than guessed.
pub const CONTRACT_VERSION: &str = "0.2";

// ---------------------------------------------------------------------------
// Part 1 — verdict vocabulary (closed taxonomy)
// ---------------------------------------------------------------------------

/// The enumerated language of what the TSPU did. Closed set: new verdicts are added by
/// minor version, existing codes never change meaning. Serializes as `{"kind": "...", ...}`.
///
/// Every variant but one is a claim about the TSPU. The exception, [`Verdict::NotEvaluated`],
/// is a claim about the *instrument* — and it is in the closed set on purpose: the failure
/// this guards against is a dead sensor whose every row reads as censorship, and a state that
/// lives outside the enum is a state a consumer can forget to check. Inside it, an exhaustive
/// `match` refuses to compile until the consumer has decided what to do with "no
/// measurement". (The first thing pulled from dpi-bench's vocabulary, 2026-09: its `exit 2 /
/// mut?` state. Its byte-level properties stay out; see CONTRACT.md Part 1.)
///
/// Derivation of each verdict from the sent-vs-arrived delta is in ECHO.md.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// Transport completed and carried traffic.
    Ok,
    /// RST injected right after the TLS SNI; TTL/IP-ID inconsistent with the real peer.
    InjectedRstAtSni,
    /// Contiguous markers arrived up to `n - 1`, then nothing, while the sender kept sending.
    SilentDropFromSegment { n: u32 },
    /// Handshake completed but sustained throughput collapsed to `bps`.
    ThrottleToRate { bps: u64 },
    /// UDP transport died while a TCP control on the same path/window survived.
    UdpClassDrop,
    /// (server-side) a Reality probe was forwarded to the real cover site.
    ActiveProbeObserved,
    /// A segment arrived but its bytes were rewritten in flight — content bytes, or the
    /// probe's own identifying header (recovered via the keyed payload; see
    /// [`EchoIntegrity`]). One verdict covers both: on the wire a rewrite of the probe
    /// header is a rewrite of UDP payload bytes like any other, and the client can act on
    /// "this path mangles bytes" but not on where in our datagram it happened.
    PayloadMutated,
    /// Died with no distinguishing shape. The honest null verdict — tracked as a
    /// first-class rate, never swept aside. This is a claim about the *path*: the probe
    /// ran to completion, its channel was sound, and still nothing distinguishing came back.
    TimeoutIndistinct,
    /// **No measurement was made.** The instrument could not run, or could not be trusted,
    /// so this row says nothing about the TSPU — not even "indistinct". Emitted by the run
    /// wrapper (never by the classifier: `probe::classify` has an [`Observation`] in hand,
    /// which means the probe did run). Excluded from every verdict rate; its own rate is an
    /// instrument-health metric. Added in contract 0.2.
    NotEvaluated {
        reason: NotEvaluatedReason,
        /// Operator-facing diagnostic (the probe's stderr tail, a path, an errno). Free
        /// text is allowed here precisely because it is *not* part of the taxonomy: nothing
        /// aggregates on it. Kept short; never a user identifier.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        detail: String,
    },
}

/// Why a run produced no measurement. Closed set, same additive-by-minor rule as
/// [`Verdict`]. Each is something the sensor can establish about *itself* before or after a
/// run — none of them is a statement about the far end, because from the RU side a dead echo
/// server and a total block are the same silence (see CONTRACT.md Part 1, `not-evaluated`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotEvaluatedReason {
    /// The probe binary is missing or not executable.
    ProbeMissing,
    /// The sensor config could not be read, or lacks a required field (`SERVER`, a
    /// well-formed `LOK_PROBE_KEY`).
    ConfigInvalid,
    /// The run lacked `CAP_NET_RAW`, so the capture that distinguishes an injected RST from a
    /// blackout could not exist — every RST-based block would have landed in
    /// `timeout_indistinct` as a false null.
    NoCapability,
    /// The probe exited non-zero before producing a verdict (bind failure, unresolvable
    /// address, panic). Its stderr is in `detail`.
    ProbeError,
    /// The probe produced output that is not a verdict this contract knows.
    MalformedVerdict,
}

impl Verdict {
    /// `false` only for [`Verdict::NotEvaluated`]. Rates, comparisons between sensors, and
    /// anything that reads "what did the TSPU do" must filter on this first; otherwise a
    /// week with a dead sensor is a week of 100 % `timeout_indistinct`-shaped nothing.
    pub fn is_measurement(&self) -> bool {
        !matches!(self, Verdict::NotEvaluated { .. })
    }
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

/// The probe battery's transports. The concrete set must track amnezia-client's real
/// transport set (see CONTRACT.md open questions), not this draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Benign TLS to a real SNI — the "is the path up at all" control.
    PlainTlsControl,
    Reality,
    AmneziaWg,
    Ss2022,
    Obfs4,
    /// Openly-synthetic, fully-labeled baseline (allowed a probe header; never dressed
    /// as a real transport, so its fingerprint doesn't matter).
    SyntheticControl,
}

impl Transport {
    /// Whether this transport rides UDP. Only AmneziaWG in the current battery.
    pub fn is_udp(self) -> bool {
        matches!(self, Transport::AmneziaWg)
    }
}

// ---------------------------------------------------------------------------
// Observation — the classifier input (the joined delta, one probe run)
// ---------------------------------------------------------------------------

/// An inbound RST seen by the sensor. `ttl_anomaly` is set by comparing this RST's TTL
/// against the clean control path's TTL — a forged (middlebox) RST rarely matches the
/// real peer's TTL/IP-ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RstInfo {
    pub ttl: u8,
    pub ip_id: u16,
    pub ttl_anomaly: bool,
}

/// What the keyed echo channel saw beyond bare arrival counts (see `lok-wire`).
///
/// These are **measurement-integrity** facts, not statements about the transport, which is
/// why they live here and not in the verdict vocabulary: "someone reflected our probe"
/// describes the instrument's channel, and the synthetic control probe's channel has no
/// counterpart in a real transport. A verdict says what happened to traffic; these say how
/// much to trust that verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoIntegrity {
    /// An arrived datagram's identifying header was rewritten in flight, and it was
    /// recovered by its keyed payload instead of its marker. Before the keyed format this
    /// read as a *drop* — a fabricated block on a path that delivered.
    pub header_mutated: bool,
    /// Echoes that were verbatim copies of the probe's own requests: something on the path
    /// bounced the probe back rather than delivering it. Never scored as arrivals.
    pub reflected: u32,
    /// Echoes carrying no valid far-end tag that could not be attributed to a sent
    /// datagram. Non-zero means something is fabricating echoes, or mangling them past
    /// recognition; either way they are not evidence of delivery.
    pub unauthenticated: u32,
    /// Whether a real shared secret was in use. Without one the tags use the published
    /// open-mode key: mutation detection still holds, forgery detection does not — so a
    /// clean verdict from an unkeyed run is a weaker claim.
    pub keyed: bool,
}

/// The joined sent-vs-arrived delta for a single probe run. Pure input to [`crate`]'s
/// consumers' classifier — carries no user identifier, no precise timestamp (see the
/// k-anon rules in CONTRACT.md Part 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub transport: Transport,
    /// Did the transport handshake complete?
    pub handshake_ok: bool,
    /// Is the TCP path reachable at all? Distinguishes a total blackout from a UDP-class
    /// kill. NOTE: stubbed `true` until the TCP-handshake probe lands.
    pub tcp_reachable: bool,
    /// Number of marked segments/datagrams the probe emitted.
    pub segments_sent: u32,
    /// Highest *contiguous* marker observed as arrived (`None` = nothing arrived).
    pub highest_marker_arrived: Option<u32>,
    /// A matching segment arrived but its payload hash differed. A rewritten *header* is
    /// reported separately in [`EchoIntegrity::header_mutated`] and maps to the same
    /// verdict — both are "bytes rewritten in flight".
    pub payload_hash_mismatch: bool,
    /// Inbound RST seen by the sensor, if any.
    pub rst: Option<RstInfo>,
    /// Measured bulk throughput, if the bulk phase ran (`None` = not measured).
    pub throughput_bps: Option<u64>,
    /// Expected bulk throughput for comparison (`None` = not measured).
    pub expected_bps: Option<u64>,
    /// Server-side: a Reality probe was forwarded to the real cover host.
    pub active_probe_forwarded: bool,
    /// Integrity of the echo channel itself. Additive: an older record without it
    /// deserializes to the all-clear default.
    #[serde(default)]
    pub echo: EchoIntegrity,
}

impl Observation {
    /// A clean, all-arrived baseline for `transport`, convenient for tests to mutate.
    pub fn baseline(transport: Transport, segments: u32) -> Self {
        Observation {
            transport,
            handshake_ok: true,
            tcp_reachable: true,
            segments_sent: segments,
            highest_marker_arrived: Some(segments.saturating_sub(1)),
            payload_hash_mismatch: false,
            rst: None,
            throughput_bps: None,
            expected_bps: None,
            active_probe_forwarded: false,
            echo: EchoIntegrity::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Part 2 — telemetry (client -> collector). k-anon; edge-aggregated.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorClass {
    /// Residential vantage — weighted highest; the signal that actually matters.
    Residential,
    /// Datacenter VPS — coarse coverage only; may sit behind a different box or none.
    Vps,
    /// Ground-truth canary; never influences a bundle.
    Dark,
}

/// Optional metrics carried with a report. Deliberately coarse; nothing here identifies
/// a reporter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rst_ttl: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highest_marker: Option<u32>,
}

/// A single outcome, k-anonymized to `{asn, region}`. Structurally carries **no** user
/// identifier, device id, precise timestamp, or GPS — the type has no field for one, by
/// design. Clients contribute to edge-aggregated counts; a raw report never leaves a
/// device below the k threshold (see CONTRACT.md Part 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReport {
    pub contract_version: String,
    pub asn: u32,
    pub region: String,
    pub transport: Transport,
    /// A cohort label, never a concrete endpoint id.
    pub endpoint_class: String,
    pub verdict: Verdict,
    #[serde(default)]
    pub metrics: Metrics,
    /// Coarse time bucket (server-correlated), not a precise stamp.
    pub bucket_start: u64,
    pub sensor_class: SensorClass,
}

// ---------------------------------------------------------------------------
// Part 3 — strategy bundle (control plane -> client). Signed; a weighted mix.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    pub asn: u32,
    pub region: String,
}

/// One transport option in the mix. `weight` is a sampling weight; `min_floor` optionally
/// keeps a transport's share from collapsing to a fleet-wide tell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleEntry {
    pub transport: Transport,
    /// A cohort the client already knows how to resolve — never a concrete endpoint, and
    /// **never** a dark endpoint.
    pub endpoint_class: String,
    pub weight: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_floor: Option<f32>,
}

/// A signed, TTL'd, single-region-slice bundle. The client **samples** the mix — it never
/// argmaxes to one transport (that would build a fleet-wide monoculture). One region slice
/// per bundle: reading one reveals one region's mix, not the map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeightedBundle {
    pub contract_version: String,
    pub issued_bucket: u64,
    pub ttl_buckets: u16,
    pub scope: Scope,
    pub mix: Vec<BundleEntry>,
    /// Signature over the whole record; key pinned in the client.
    #[serde(with = "serde_bytes_vec")]
    pub signature: Vec<u8>,
}

impl WeightedBundle {
    /// Placeholder verification. Real ed25519 lands with the control plane (Phase 2).
    pub fn verify_stub(&self, _pubkey: &[u8]) -> bool {
        true
    }

    /// Sample a transport by weight given a uniform draw in `[0, 1)`. Encodes the
    /// never-argmax invariant: the client picks by weighted sampling, not "best".
    /// Returns `None` only if the mix is empty or weights sum to zero.
    pub fn sample(&self, draw: f32) -> Option<&BundleEntry> {
        let total: f32 = self.mix.iter().map(|e| e.weight.max(0.0)).sum();
        if total <= 0.0 {
            return None;
        }
        let mut cursor = draw.clamp(0.0, 1.0) * total;
        for entry in &self.mix {
            cursor -= entry.weight.max(0.0);
            if cursor < 0.0 {
                return Some(entry);
            }
        }
        self.mix.last()
    }
}

/// Minimal `Vec<u8>` (de)serialization that stays legible in JSON. Kept local to avoid a
/// serde_bytes dependency; the wire format is a plain array of bytes.
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().copied())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_json_shape_matches_contract() {
        let v = Verdict::SilentDropFromSegment { n: 4 };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"kind":"silent_drop_from_segment","n":4}"#
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Ok).unwrap(),
            r#"{"kind":"ok"}"#
        );
    }

    /// The run wrapper (`deploy/run-battery.sh`) writes `not_evaluated` rows by hand, in
    /// bash, so the exact strings it emits are pinned here: if this shape drifts the wrapper
    /// and the contract disagree and the row becomes `malformed` at best.
    #[test]
    fn not_evaluated_json_shape_matches_the_wrapper() {
        let v = Verdict::NotEvaluated {
            reason: NotEvaluatedReason::NoCapability,
            detail: "CapEff lacks CAP_NET_RAW".into(),
        };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"kind":"not_evaluated","reason":"no_capability","detail":"CapEff lacks CAP_NET_RAW"}"#
        );
        // `detail` is optional on the wire.
        let bare: Verdict =
            serde_json::from_str(r#"{"kind":"not_evaluated","reason":"probe_missing"}"#).unwrap();
        assert_eq!(bare, Verdict::NotEvaluated { reason: NotEvaluatedReason::ProbeMissing, detail: String::new() });
        // Every reason the wrapper can emit round-trips.
        for r in ["probe_missing", "config_invalid", "no_capability", "probe_error", "malformed_verdict"] {
            let s = format!(r#"{{"kind":"not_evaluated","reason":"{r}"}}"#);
            let v: Verdict = serde_json::from_str(&s).unwrap_or_else(|e| panic!("{r}: {e}"));
            assert!(!v.is_measurement());
        }
    }

    #[test]
    fn every_real_verdict_is_a_measurement() {
        for v in [
            Verdict::Ok,
            Verdict::InjectedRstAtSni,
            Verdict::SilentDropFromSegment { n: 0 },
            Verdict::ThrottleToRate { bps: 1 },
            Verdict::UdpClassDrop,
            Verdict::ActiveProbeObserved,
            Verdict::PayloadMutated,
            Verdict::TimeoutIndistinct,
        ] {
            assert!(v.is_measurement(), "{v:?}");
        }
    }

    #[test]
    fn bundle_samples_by_weight_never_panics_on_edges() {
        let bundle = WeightedBundle {
            contract_version: CONTRACT_VERSION.to_string(),
            issued_bucket: 0,
            ttl_buckets: 6,
            scope: Scope { asn: 12389, region: "ru-nw".into() },
            mix: vec![
                BundleEntry { transport: Transport::Reality, endpoint_class: "a".into(), weight: 0.7, min_floor: Some(0.1) },
                BundleEntry { transport: Transport::AmneziaWg, endpoint_class: "b".into(), weight: 0.3, min_floor: None },
            ],
            signature: vec![],
        };
        assert!(bundle.verify_stub(b"pk"));
        assert_eq!(bundle.sample(0.0).unwrap().transport, Transport::Reality);
        assert_eq!(bundle.sample(0.99).unwrap().transport, Transport::AmneziaWg);
        // empty mix -> None
        let mut empty = bundle.clone();
        empty.mix.clear();
        assert!(empty.sample(0.5).is_none());
    }
}
