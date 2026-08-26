//! Phase 1 step-0 calibration (synthetic + one real loopback).
//!
//! Each synthetic case injects a known delta shape and asserts the classifier recovers the
//! intended verdict. The loopback case runs the real UDP battery against a real echo server
//! with a known drop policy — proving probe + classifier agree on ground truth end-to-end.
//! Every verdict path added to the taxonomy gets a case here before it is trusted live.

use std::net::UdpSocket;
use std::thread;

use echo_server::{serve, DropPolicy};
use lok_contract::{Observation, RstInfo, Transport, Verdict};
use probe::{classify, probe_once};

#[test]
fn clean_path_is_ok() {
    let obs = Observation::baseline(Transport::PlainTlsControl, 8);
    assert_eq!(classify(&obs), Verdict::Ok);
}

#[test]
fn drop_after_four_is_silent_drop_from_segment() {
    let mut obs = Observation::baseline(Transport::SyntheticControl, 8);
    obs.highest_marker_arrived = Some(3); // markers 0..=3 arrived, then nothing
    assert_eq!(classify(&obs), Verdict::SilentDropFromSegment { n: 4 });
}

#[test]
fn nothing_arrives_from_the_start_is_drop_from_zero() {
    let mut obs = Observation::baseline(Transport::Reality, 8);
    obs.highest_marker_arrived = None;
    obs.handshake_ok = false;
    obs.tcp_reachable = true; // path up, but this TCP transport delivered nothing
    assert_eq!(classify(&obs), Verdict::SilentDropFromSegment { n: 0 });
}

#[test]
fn udp_silent_with_tcp_up_is_udp_class_drop() {
    let mut obs = Observation::baseline(Transport::AmneziaWg, 8);
    obs.highest_marker_arrived = None;
    obs.handshake_ok = false;
    obs.tcp_reachable = true;
    assert_eq!(classify(&obs), Verdict::UdpClassDrop);
}

#[test]
fn anomalous_rst_ttl_is_injected_rst() {
    let mut obs = Observation::baseline(Transport::Reality, 8);
    obs.rst = Some(RstInfo { ttl: 200, ip_id: 0, ttl_anomaly: true });
    assert_eq!(classify(&obs), Verdict::InjectedRstAtSni);
}

#[test]
fn mutated_payload_is_payload_mutated() {
    let mut obs = Observation::baseline(Transport::Ss2022, 8);
    obs.payload_hash_mismatch = true;
    assert_eq!(classify(&obs), Verdict::PayloadMutated);
}

#[test]
fn slow_transfer_is_throttled() {
    let mut obs = Observation::baseline(Transport::Ss2022, 8);
    obs.throughput_bps = Some(120_000);
    obs.expected_bps = Some(10_000_000);
    assert_eq!(classify(&obs), Verdict::ThrottleToRate { bps: 120_000 });
}

#[test]
fn forwarded_reality_probe_is_active_probe_observed() {
    let mut obs = Observation::baseline(Transport::Reality, 8);
    obs.active_probe_forwarded = true;
    assert_eq!(classify(&obs), Verdict::ActiveProbeObserved);
}

#[test]
fn total_blackout_is_timeout_indistinct() {
    let mut obs = Observation::baseline(Transport::PlainTlsControl, 8);
    obs.highest_marker_arrived = None;
    obs.handshake_ok = false;
    obs.tcp_reachable = false; // nothing anywhere, no distinguishing shape
    assert_eq!(classify(&obs), Verdict::TimeoutIndistinct);
}

/// Real end-to-end: a live echo server dropping markers >= 4, the real UDP probe, and the
/// classifier — all agreeing on `silent_drop_from_segment{n:4}` against ground truth.
#[test]
fn loopback_real_drop_recovers_silent_drop() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind echo server");
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let _ = serve(server, DropPolicy::DropFromMarker(4));
    });

    let obs = probe_once(&addr.to_string(), 8).expect("probe run");
    assert_eq!(classify(&obs), Verdict::SilentDropFromSegment { n: 4 });
}
