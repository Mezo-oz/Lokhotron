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
pub const CONTRACT_VERSION: &str = "0.1";

// ---------------------------------------------------------------------------
// Part 1 — verdict vocabulary (closed taxonomy)
// ---------------------------------------------------------------------------

/// The enumerated language of what the TSPU did. Closed set: new verdicts are added by
/// minor version, existing codes never change meaning. Serializes as `{"kind": "...", ...}`.
///
/// Reconcile against dpi-bench's property vocabulary as it firms up (one-way pull; see
/// CONTRACT.md Part 1). Derivation of each verdict from the sent-vs-arrived delta is in ECHO.md.
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
    /// A matching segment arrived but its payload bytes were rewritten in flight.
    PayloadMutated,
    /// Died with no distinguishing shape. The honest null verdict — tracked as a
    /// first-class rate, never swept aside.
    TimeoutIndistinct,
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
    /// A matching segment arrived but its payload hash differed.
    pub payload_hash_mismatch: bool,
    /// Inbound RST seen by the sensor, if any.
    pub rst: Option<RstInfo>,
    /// Measured bulk throughput, if the bulk phase ran (`None` = not measured).
    pub throughput_bps: Option<u64>,
    /// Expected bulk throughput for comparison (`None` = not measured).
    pub expected_bps: Option<u64>,
    /// Server-side: a Reality probe was forwarded to the real cover host.
    pub active_probe_forwarded: bool,
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
