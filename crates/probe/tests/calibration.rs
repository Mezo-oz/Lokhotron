//! Phase 1 step-0 calibration (synthetic + one real loopback).
//!
//! Each synthetic case injects a known delta shape and asserts the classifier recovers the
//! intended verdict. The loopback case runs the real UDP battery against a real echo server
//! with a known drop policy — proving probe + classifier agree on ground truth end-to-end.
//! Every verdict path added to the taxonomy gets a case here before it is trusted live.

use std::net::{TcpListener, UdpSocket};
use std::thread;

use echo_server::{serve, serve_tcp, DropPolicy};
use lok_contract::{Observation, RstInfo, Transport, Verdict};
use probe::{classify, measure_throughput, probe_battery, probe_once, tcp_reachable};

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

/// Spin up a full echo endpoint (UDP marked-echo + TCP byte-echo) on one address and return
/// it. `drop` applies to the UDP side only.
fn spawn_echo(drop: DropPolicy) -> String {
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).expect("bind tcp same port");
    thread::spawn(move || {
        let _ = serve(udp, drop);
    });
    thread::spawn(move || {
        let _ = serve_tcp(tcp);
    });
    addr.to_string()
}

#[test]
fn tcp_reachable_true_when_listener_up_false_when_not() {
    let addr = spawn_echo(DropPolicy::None);
    assert!(tcp_reachable(&addr));
    // An address with no listener: reserve a port, drop the listener, then probe it.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap().to_string();
    drop(dead);
    assert!(!tcp_reachable(&dead_addr));
}

#[test]
fn throughput_measures_a_positive_rate() {
    let addr = spawn_echo(DropPolicy::None);
    let bps = measure_throughput(&addr).expect("some throughput on loopback");
    assert!(bps > 0);
}

/// The key fix: UDP fully blackout while TCP is up must classify as `udp_class_drop`, not
/// be masked by a stubbed `tcp_reachable`. Uses the real battery against a real endpoint.
#[test]
fn battery_udp_blackout_tcp_up_is_udp_class_drop() {
    let addr = spawn_echo(DropPolicy::DropFromMarker(0)); // drop every UDP marker
    let obs = probe_battery(&addr, &addr, 8).expect("battery run");
    assert!(obs.tcp_reachable, "TCP echo is up, so reachable must be measured true");
    assert_eq!(obs.highest_marker_arrived, None, "no UDP marker survived");
    assert_eq!(classify(&obs), Verdict::UdpClassDrop);
}

/// A healthy battery run (UDP all-arrive, TCP up, loopback throughput far above expected)
/// classifies as Ok — throughput does not trip a false `throttled`.
#[test]
fn battery_clean_path_is_ok() {
    let addr = spawn_echo(DropPolicy::None);
    let obs = probe_battery(&addr, &addr, 8).expect("battery run");
    assert!(obs.tcp_reachable);
    assert_eq!(classify(&obs), Verdict::Ok);
}
