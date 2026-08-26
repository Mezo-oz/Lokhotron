//! The RU-side sensor.
//!
//! [`classify`] is a **pure function** of the joined delta — no I/O, fully unit-testable,
//! and the single place a verdict is decided. [`probe_once`] performs the live UDP battery
//! run and builds the [`Observation`] that feeds it.
//!
//! Current limits (see STATUS.md / ECHO.md): the battery is UDP-only, so `tcp_reachable`
//! is stubbed `true`, and `injected_rst` / `payload_mutated` / `throttled` are exercised
//! only via synthetic Observations until the TCP-handshake probe lands.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use lok_contract::{Observation, RstInfo, Transport, Verdict};

/// Fraction of expected throughput below which the path is judged throttled.
const THROTTLE_FRACTION: f64 = 0.5;

/// Nominal healthy rate a transport is expected to sustain. Compared against measured
/// throughput to detect `throttle_to_rate`. Coarse on purpose.
pub const EXPECTED_BPS: u64 = 5_000_000;

/// Bulk volume pushed through the TCP echo to measure throughput.
const BULK_BYTES: usize = 256 * 1024;

/// Assumed clean-path TTL for the route, against which an RST's TTL is compared to detect a
/// forged (middlebox) RST. A real deployment calibrates this per route from a control
/// connection; 64 is the common Linux default and what the netns rig uses.
pub const DEFAULT_CONTROL_TTL: u8 = 64;

fn resolve(addr: &str) -> Option<SocketAddr> {
    addr.to_socket_addrs().ok()?.next()
}

/// Decide the verdict from a single run's joined delta. Pure: same `Observation` in, same
/// `Verdict` out. Derivation table lives in ECHO.md §5.
pub fn classify(obs: &Observation) -> Verdict {
    // Server-side signal is authoritative when present.
    if obs.active_probe_forwarded {
        return Verdict::ActiveProbeObserved;
    }

    // A forged RST self-identifies by an anomalous TTL vs the clean control path.
    if let Some(rst) = obs.rst {
        if rst.ttl_anomaly {
            return Verdict::InjectedRstAtSni;
        }
    }

    // A matching segment arrived but its bytes were rewritten.
    if obs.payload_hash_mismatch {
        return Verdict::PayloadMutated;
    }

    // UDP-class drop: a UDP transport delivered nothing while the TCP path is up.
    if obs.transport.is_udp() && obs.highest_marker_arrived.is_none() && obs.tcp_reachable {
        return Verdict::UdpClassDrop;
    }

    match obs.highest_marker_arrived {
        // Some contiguous prefix arrived.
        Some(high) => {
            let arrived = high + 1; // markers 0..=high
            if arrived < obs.segments_sent {
                return Verdict::SilentDropFromSegment { n: arrived };
            }
            // Everything arrived. Check for throttling on an otherwise-complete transfer.
            if obs.handshake_ok {
                if let (Some(tp), Some(exp)) = (obs.throughput_bps, obs.expected_bps) {
                    if exp > 0 && (tp as f64) < THROTTLE_FRACTION * (exp as f64) {
                        return Verdict::ThrottleToRate { bps: tp };
                    }
                }
                return Verdict::Ok;
            }
            Verdict::TimeoutIndistinct
        }
        // Nothing arrived at all.
        None => {
            if !obs.tcp_reachable {
                // Total blackout with no distinguishing shape.
                Verdict::TimeoutIndistinct
            } else {
                // Path is up but not one byte of this transport survived from the start.
                Verdict::SilentDropFromSegment { n: 0 }
            }
        }
    }
}

/// Run one UDP marked-echo battery against `server` with `count` datagrams, and build the
/// resulting [`Observation`]. Datagram layout matches the echo server: `[nonce][marker]`.
pub fn probe_once(server: &str, count: u32) -> std::io::Result<Observation> {
    const NONCE: u32 = 0xA1B2_C3D4;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(server)?;
    sock.set_read_timeout(Some(Duration::from_millis(300)))?;

    for marker in 0..count {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&NONCE.to_be_bytes());
        buf[4..8].copy_from_slice(&marker.to_be_bytes());
        sock.send(&buf)?;
    }

    let mut arrived = vec![false; count as usize];
    let mut recv = [0u8; 64];
    loop {
        match sock.recv(&mut recv) {
            Ok(n) if n >= 8 => {
                let rn = u32::from_be_bytes(recv[0..4].try_into().unwrap());
                let rm = u32::from_be_bytes(recv[4..8].try_into().unwrap());
                if rn == NONCE && (rm as usize) < arrived.len() {
                    arrived[rm as usize] = true;
                }
            }
            Ok(_) => {}
            Err(_) => break, // read timeout: no more echoes coming
        }
    }

    // Highest *contiguous* marker that arrived.
    let mut highest = None;
    for (i, &a) in arrived.iter().enumerate() {
        if a {
            highest = Some(i as u32);
        } else {
            break;
        }
    }

    Ok(Observation {
        transport: Transport::AmneziaWg, // UDP battery representative
        handshake_ok: highest.is_some(),
        tcp_reachable: true, // UDP-only entry point assumes the path; probe_battery measures it
        segments_sent: count,
        highest_marker_arrived: highest,
        payload_hash_mismatch: false,
        rst: None,
        throughput_bps: None,
        expected_bps: None,
        active_probe_forwarded: false,
    })
}

/// Attempt a real TCP handshake to `addr`. A success means the TCP path is up — which is
/// what separates a *total blackout* from a *UDP-class kill* (UDP dead, TCP alive).
pub fn tcp_reachable(addr: &str) -> bool {
    resolve(addr)
        .map(|sa| TcpStream::connect_timeout(&sa, Duration::from_millis(500)).is_ok())
        .unwrap_or(false)
}

/// The outcome of the TCP half of the battery: whether the path is up, and any inbound RST
/// the sensor saw during the handshake attempt.
pub struct TcpProbeResult {
    pub reachable: bool,
    pub rst: Option<RstInfo>,
}

/// The TCP-probe seam. A real run captures below the stack to catch an injected RST; tests
/// inject a fake to exercise the wiring without root. `control_ttl` is the clean-path TTL an
/// observed RST is judged against.
pub trait TcpProbe {
    fn run(&self, tcp_addr: &str, control_ttl: u8) -> TcpProbeResult;
}

/// TCP probe with no capture: reachability only, never reports an RST. Used off-Linux and as
/// the graceful fallback when the capture socket can't be opened (no `CAP_NET_RAW`).
pub struct PlainTcpProbe;

impl TcpProbe for PlainTcpProbe {
    fn run(&self, tcp_addr: &str, _control_ttl: u8) -> TcpProbeResult {
        let reachable = resolve(tcp_addr)
            .map(|sa| TcpStream::connect_timeout(&sa, Duration::from_millis(500)).is_ok())
            .unwrap_or(false);
        TcpProbeResult { reachable, rst: None }
    }
}

/// TCP probe that runs an `AF_PACKET` capture during the handshake and reports any RST it
/// sees, with its TTL judged against `control_ttl`. Linux + `CAP_NET_RAW`; degrades to
/// [`PlainTcpProbe`] when the capture socket can't be opened, so a non-root run just yields
/// `rst: None` rather than failing. The end-to-end capture path is validated under the netns
/// rig (root), not `cargo test`.
#[cfg(target_os = "linux")]
pub struct CapturingTcpProbe;

#[cfg(target_os = "linux")]
impl TcpProbe for CapturingTcpProbe {
    fn run(&self, tcp_addr: &str, control_ttl: u8) -> TcpProbeResult {
        let cap = match lok_capture::AfPacketCapture::open() {
            Ok(c) => c,
            Err(_) => return PlainTcpProbe.run(tcp_addr, control_ttl), // no CAP_NET_RAW
        };
        let Some(sa) = resolve(tcp_addr) else {
            return TcpProbeResult { reachable: false, rst: None };
        };
        let deadline = Instant::now() + Duration::from_millis(700);
        let watcher = std::thread::spawn(move || cap.watch_for_rst(control_ttl, deadline).ok().flatten());
        std::thread::sleep(Duration::from_millis(50)); // let the capture start listening
        let reachable = TcpStream::connect_timeout(&sa, Duration::from_millis(500)).is_ok();
        let rst = watcher
            .join()
            .ok()
            .flatten()
            .map(|(p, anomaly)| RstInfo { ttl: p.ttl, ip_id: p.ip_id, ttl_anomaly: anomaly });
        TcpProbeResult { reachable, rst }
    }
}

#[cfg(target_os = "linux")]
fn default_tcp_probe() -> Box<dyn TcpProbe> {
    Box::new(CapturingTcpProbe)
}

#[cfg(not(target_os = "linux"))]
fn default_tcp_probe() -> Box<dyn TcpProbe> {
    Box::new(PlainTcpProbe)
}

/// Push `BULK_BYTES` through the TCP echo and time the round trip, returning bits/sec.
/// A concurrent writer thread avoids the send/recv deadlock on a full socket buffer.
/// `None` if the connection fails or nothing echoes back.
pub fn measure_throughput(addr: &str) -> Option<u64> {
    let stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut reader = stream.try_clone().ok()?;
    let mut writer = stream;

    let start = Instant::now();
    let writer_thread = std::thread::spawn(move || {
        let chunk = [0x5Au8; 4096];
        let mut left = BULK_BYTES;
        while left > 0 {
            let n = left.min(chunk.len());
            if writer.write_all(&chunk[..n]).is_err() {
                break;
            }
            left -= n;
        }
        let _ = writer.flush();
        let _ = writer.shutdown(std::net::Shutdown::Write);
    });

    let mut got = 0usize;
    let mut buf = [0u8; 8192];
    while got < BULK_BYTES {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => break,
        }
    }
    let _ = writer_thread.join();

    let secs = start.elapsed().as_secs_f64();
    if secs <= 0.0 || got == 0 {
        return None;
    }
    Some(((got as f64) * 8.0 / secs) as u64)
}

/// The real battery: run the UDP marked-echo delta, then probe the TCP path — filling
/// `tcp_reachable` (blackout vs UDP-class kill), `rst` (on-wire `injected_rst_at_sni` via the
/// capture), and `throughput_bps`/`expected_bps` (real `throttle_to_rate`). Uses the default
/// TCP probe: capturing on Linux (root), plain otherwise.
pub fn probe_battery(udp_addr: &str, tcp_addr: &str, count: u32) -> std::io::Result<Observation> {
    let tcp = default_tcp_probe();
    probe_battery_with(udp_addr, tcp_addr, count, tcp.as_ref(), DEFAULT_CONTROL_TTL)
}

/// [`probe_battery`] with an injectable TCP probe and control TTL, so the RST wiring can be
/// exercised with a fake reset in tests (no root) and the real capture under the rig.
pub fn probe_battery_with(
    udp_addr: &str,
    tcp_addr: &str,
    count: u32,
    tcp: &dyn TcpProbe,
    control_ttl: u8,
) -> std::io::Result<Observation> {
    let mut obs = probe_once(udp_addr, count)?;
    let res = tcp.run(tcp_addr, control_ttl);
    obs.tcp_reachable = res.reachable;
    obs.rst = res.rst;
    // A reset connection carries no throughput; only measure when the path stayed up.
    if obs.tcp_reachable {
        if let Some(bps) = measure_throughput(tcp_addr) {
            obs.throughput_bps = Some(bps);
            obs.expected_bps = Some(EXPECTED_BPS);
        }
    }
    Ok(obs)
}
