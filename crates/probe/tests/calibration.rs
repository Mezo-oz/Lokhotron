//! Phase 1 step-0 calibration (synthetic + real loopback).
//!
//! Each synthetic case injects a known delta shape and asserts the classifier recovers the
//! intended verdict. The loopback cases run the real UDP battery against a real echo server
//! with a known fault policy — proving probe + classifier agree on ground truth end-to-end.
//! Every verdict path added to the taxonomy gets a case here before it is trusted live.

use std::net::{TcpListener, UdpSocket};
use std::thread;

use echo_server::{serve, serve_tcp, FaultPolicy};
use lok_contract::{Observation, RstInfo, Transport, Verdict};
use lok_wire::{build_response, Key, DATAGRAM_LEN, PAYLOAD_OFF};
use probe::{
    classify, measure_throughput, probe_battery, probe_battery_with, probe_once_with_key,
    tcp_reachable, TcpProbe, TcpProbeResult,
};

/// A TCP probe that pretends the connection was reset by a middlebox with an anomalous TTL —
/// stands in for the root-gated AF_PACKET capture so the RST wiring is testable without root.
struct FakeReset;
impl TcpProbe for FakeReset {
    fn run(&self, _tcp_addr: &str, _control_ttl: u8) -> TcpProbeResult {
        TcpProbeResult {
            reachable: false,
            rst: Some(RstInfo { ttl: 200, ip_id: 0xBEEF, ttl_anomaly: true }),
        }
    }
}

// ---------------------------------------------------------------------------
// Synthetic: the classifier against known delta shapes
// ---------------------------------------------------------------------------

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
    let mut obs = Observation::baseline(Transport::XrayReality, 8);
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
    let mut obs = Observation::baseline(Transport::XrayReality, 8);
    obs.rst = Some(RstInfo { ttl: 200, ip_id: 0, ttl_anomaly: true });
    assert_eq!(classify(&obs), Verdict::InjectedRstAtSni);
}

#[test]
fn mutated_payload_is_payload_mutated() {
    let mut obs = Observation::baseline(Transport::Shadowsocks, 8);
    obs.payload_hash_mismatch = true;
    assert_eq!(classify(&obs), Verdict::PayloadMutated);
}

/// A rewritten probe header is the same verdict as rewritten content: both are bytes
/// rewritten in flight. What must *not* happen is the pre-keyed behaviour, where the
/// datagram stopped being recognizable and the run reported a drop that never occurred.
#[test]
fn mutated_header_is_payload_mutated_not_a_drop() {
    let mut obs = Observation::baseline(Transport::SyntheticControl, 8);
    obs.echo.header_mutated = true;
    assert_eq!(classify(&obs), Verdict::PayloadMutated);
}

#[test]
fn slow_transfer_is_throttled() {
    let mut obs = Observation::baseline(Transport::Shadowsocks, 8);
    obs.throughput_bps = Some(120_000);
    obs.expected_bps = Some(10_000_000);
    assert_eq!(classify(&obs), Verdict::ThrottleToRate { bps: 120_000 });
}

#[test]
fn forwarded_reality_probe_is_active_probe_observed() {
    let mut obs = Observation::baseline(Transport::XrayReality, 8);
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

// ---------------------------------------------------------------------------
// Loopback: the real probe against a real server
// ---------------------------------------------------------------------------

/// The key both ends of every loopback case run with. Tests never read `LOK_PROBE_KEY`:
/// a developer's shell must not be able to change what these assert.
fn test_key() -> Key {
    Key::from_hex(&"7c".repeat(32)).expect("valid test key")
}

/// Spin up a UDP-only marked-echo server with a known fault policy.
fn spawn_udp_echo(fault: FaultPolicy) -> String {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind echo server");
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        let _ = serve(server, fault, test_key());
    });
    addr.to_string()
}

/// Spin up a full echo endpoint (UDP marked-echo + TCP byte-echo) on one address and return
/// it. `fault` applies to the UDP side only.
fn spawn_echo(fault: FaultPolicy) -> String {
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).expect("bind tcp same port");
    thread::spawn(move || {
        let _ = serve(udp, fault, test_key());
    });
    thread::spawn(move || {
        let _ = serve_tcp(tcp);
    });
    addr.to_string()
}

/// A UDP endpoint that answers correctly and then lets `mangle` rewrite the reply on its
/// way out — an in-flight rewrite on the return leg, which is what the rig's nftables cases
/// do mid-path. Returns the address.
fn spawn_mangling_echo(mangle: fn(&mut [u8; DATAGRAM_LEN])) -> String {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind mangling echo");
    let addr = sock.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            if n != DATAGRAM_LEN {
                continue;
            }
            let req: [u8; DATAGRAM_LEN] = buf[..DATAGRAM_LEN].try_into().unwrap();
            let mut reply = build_response(&test_key(), &req);
            mangle(&mut reply);
            let _ = sock.send_to(&reply, peer);
        }
    });
    addr
}

/// Real end-to-end: a live echo server dropping markers >= 4, the real UDP probe, and the
/// classifier — all agreeing on `silent_drop_from_segment{n:4}` against ground truth.
#[test]
fn loopback_real_drop_recovers_silent_drop() {
    let addr = spawn_udp_echo(FaultPolicy::DropFromMarker(4));
    let obs = probe_once_with_key(&addr, 8, test_key()).expect("probe run");
    assert_eq!(classify(&obs), Verdict::SilentDropFromSegment { n: 4 });
}

#[test]
fn tcp_reachable_true_when_listener_up_false_when_not() {
    let addr = spawn_echo(FaultPolicy::None);
    assert!(tcp_reachable(&addr));
    // An address with no listener: reserve a port, drop the listener, then probe it.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap().to_string();
    drop(dead);
    assert!(!tcp_reachable(&dead_addr));
}

#[test]
fn throughput_measures_a_positive_rate() {
    let addr = spawn_echo(FaultPolicy::None);
    let bps = measure_throughput(&addr).expect("some throughput on loopback");
    assert!(bps > 0);
}

/// The key fix: UDP fully blackout while TCP is up must classify as `udp_class_drop`, not
/// be masked by a stubbed `tcp_reachable`. Uses the real battery against a real endpoint.
#[test]
fn battery_udp_blackout_tcp_up_is_udp_class_drop() {
    let addr = spawn_echo(FaultPolicy::DropFromMarker(0)); // drop every UDP marker
    let obs = probe_battery(&addr, &addr, 8).expect("battery run");
    assert!(obs.tcp_reachable, "TCP echo is up, so reachable must be measured true");
    assert_eq!(obs.highest_marker_arrived, None, "no UDP marker survived");
    assert_eq!(classify(&obs), Verdict::UdpClassDrop);
}

/// A healthy battery run (UDP all-arrive, TCP up, loopback throughput far above expected)
/// classifies as Ok — throughput does not trip a false `throttled`.
#[test]
fn battery_clean_path_is_ok() {
    let addr = spawn_echo(FaultPolicy::None);
    let obs = probe_battery_with(&addr, &addr, 8, &probe::PlainTcpProbe, 64, test_key())
        .expect("battery run");
    assert!(obs.tcp_reachable);
    assert_eq!(classify(&obs), Verdict::Ok);
}

/// The RST wiring: an injected reset with an anomalous TTL, observed by the TCP probe, must
/// flow through `probe_battery_with` into `Observation.rst` and classify as
/// `injected_rst_at_sni` — regardless of the UDP delta. Uses a fake reset to stand in for
/// the root-gated capture; the real capture path is the netns rig's RST case.
#[test]
fn battery_injected_rst_classifies_on_wire() {
    let addr = spawn_echo(FaultPolicy::None); // UDP would be clean; the RST must still win
    let obs = probe_battery_with(&addr, &addr, 8, &FakeReset, 64, test_key()).expect("battery run");
    assert_eq!(obs.rst.map(|r| r.ttl_anomaly), Some(true));
    assert!(!obs.tcp_reachable, "a reset connection is not reachable");
    assert_eq!(classify(&obs), Verdict::InjectedRstAtSni);
}

// ---------------------------------------------------------------------------
// The keyed channel: what may be counted as an arrival
// ---------------------------------------------------------------------------

/// A clean echo must not raise a false mutation or integrity signal — the failure mode that
/// would make every verdict useless live.
#[test]
fn clean_echo_reports_no_mutation_and_no_integrity_noise() {
    let addr = spawn_udp_echo(FaultPolicy::None);
    let obs = probe_once_with_key(&addr, 8, test_key()).expect("probe run");
    assert!(!obs.payload_hash_mismatch);
    assert!(!obs.echo.header_mutated);
    assert_eq!((obs.echo.reflected, obs.echo.unauthenticated), (0, 0));
    assert!(obs.echo.keyed, "a configured key must be reported as keyed");
    assert_eq!(classify(&obs), Verdict::Ok);
}

/// Real end-to-end: one payload byte rewritten on the way back. Every marker still arrives,
/// so only the sent-vs-returned comparison can see it. The rig's nftables case does the
/// same thing mid-path.
#[test]
fn rewritten_payload_recovers_payload_mutated() {
    let addr = spawn_mangling_echo(|reply| reply[PAYLOAD_OFF] ^= 0xFF);
    let obs = probe_once_with_key(&addr, 8, test_key()).expect("probe run");
    assert_eq!(obs.highest_marker_arrived, Some(7), "every marker still arrives");
    assert!(obs.payload_hash_mismatch);
    assert_eq!(classify(&obs), Verdict::PayloadMutated);
}

/// The caveat this format exists to close. A rewrite of the *marker* used to make the echo
/// unrecognizable, so the run reported `silent_drop_from_segment{n:0}` — a fabricated block
/// on a path that delivered every datagram. The keyed payload still names each datagram, so
/// it now reads as the mutation it is.
#[test]
fn rewritten_header_is_recovered_not_reported_as_a_drop() {
    let addr = spawn_mangling_echo(|reply| reply[4] = 0xFF); // marker's high byte
    let obs = probe_once_with_key(&addr, 8, test_key()).expect("probe run");
    assert_eq!(obs.highest_marker_arrived, Some(7), "every marker is still recovered");
    assert!(obs.echo.header_mutated);
    assert_eq!(classify(&obs), Verdict::PayloadMutated);
}

/// The other half of the key's job. A middlebox that swallows the traffic and bounces the
/// probe's own datagrams back cannot make a dead path read as healthy: a request tag is not
/// a response tag, so none of these count as arrivals.
#[test]
fn a_reflector_cannot_fake_delivery() {
    let addr = spawn_echo(FaultPolicy::ReflectVerbatim);
    let obs = probe_battery_with(&addr, &addr, 8, &probe::PlainTcpProbe, 64, test_key())
        .expect("battery run");
    assert_eq!(obs.highest_marker_arrived, None, "a reflected request is not delivery");
    assert_eq!(obs.echo.reflected, 8, "and every one of them is counted as what it was");
    assert_eq!(classify(&obs), Verdict::UdpClassDrop);
}

/// An impostor holding the wrong key is in the same position as the reflector: it can send
/// well-formed datagrams, but nothing it signs is evidence of delivery.
#[test]
fn an_impostor_with_the_wrong_key_is_not_delivery() {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind impostor");
    let addr = sock.local_addr().unwrap().to_string();
    let wrong = Key::from_hex(&"aa".repeat(32)).unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            if n != DATAGRAM_LEN {
                continue;
            }
            let req: [u8; DATAGRAM_LEN] = buf[..DATAGRAM_LEN].try_into().unwrap();
            let _ = sock.send_to(&build_response(&wrong, &req), peer);
        }
    });

    let obs = probe_once_with_key(&addr, 8, test_key()).expect("probe run");
    assert_eq!(obs.highest_marker_arrived, None);
    assert_eq!(obs.echo.unauthenticated, 8);
    assert!(!obs.payload_hash_mismatch, "an unsigned datagram is not evidence of a rewrite");
}

/// The admission check, from the outside: unauthenticated traffic gets no reply at all, so
/// a public sensor endpoint cannot be used to reflect packets at a third party.
#[test]
fn the_server_does_not_answer_unauthenticated_traffic() {
    let addr = spawn_udp_echo(FaultPolicy::None);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.connect(&addr).unwrap();
    client.set_read_timeout(Some(std::time::Duration::from_millis(300))).unwrap();

    client.send(&[0x42u8; DATAGRAM_LEN]).unwrap();
    let mut buf = [0u8; 2048];
    assert!(client.recv(&mut buf).is_err(), "junk must draw no reply");

    // And the same endpoint answers a real run, so the silence above is the check working
    // rather than the server being down.
    let obs = probe_once_with_key(&addr, 4, test_key()).expect("probe run");
    assert_eq!(obs.highest_marker_arrived, Some(3));
}
