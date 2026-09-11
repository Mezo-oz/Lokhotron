//! The RU-side sensor.
//!
//! [`classify`] is a **pure function** of the joined delta — no I/O, fully unit-testable,
//! and the single place a verdict is decided. [`probe_battery`] performs the live run
//! (UDP marked-echo + TCP handshake/throughput) and builds the [`Observation`] that feeds it.
//!
//! Every capture the battery runs is scoped to a [`FlowFilter`] built from a socket the
//! probe bound *before* opening the capture, so a packet from an unrelated flow on the same
//! box can never be read as a measurement of this path (see lok-capture's module docs).
//!
//! The UDP datagrams are `lok-wire`'s keyed v2 format, which is what makes an *arrival* a
//! claim the probe can defend: an echo only counts if the far end signed it with the shared
//! key, and a datagram whose header was rewritten in flight is still recovered — by its
//! keyed payload — instead of being counted as a drop that never happened.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use lok_contract::{EchoIntegrity, Observation, RstInfo, Transport, Verdict};
use lok_wire::{Echo, Key, Leg, SentRun, CALIBRATION_NONCE, KEY_ENV, PROBE_NONCE};

/// Fraction of expected throughput below which the path is judged throttled.
const THROTTLE_FRACTION: f64 = 0.5;

/// Nominal healthy rate a transport is expected to sustain. Compared against measured
/// throughput to detect `throttle_to_rate`. Coarse on purpose.
pub const EXPECTED_BPS: u64 = 5_000_000;

/// Bulk volume pushed through the TCP echo to measure throughput.
const BULK_BYTES: usize = 256 * 1024;

/// Fallback clean-path TTL, used only when per-route calibration ([`calibrate_control_ttl`])
/// can't measure the real peer (no `CAP_NET_RAW`, or no reply). 64 is the common Linux
/// default. The battery prefers a measured value.
pub const DEFAULT_CONTROL_TTL: u8 = 64;

/// The shared secret both ends of the delta hold, from `LOK_PROBE_KEY`. Falls back to
/// `lok-wire`'s published open-mode key with a warning: an unkeyed run still measures
/// drops and mutations (both ends agree on the tags either way), it just cannot prove the
/// far end is the one that echoed. `Observation.echo.keyed` records which it was, so a
/// verdict is never read as a stronger claim than the run supports.
pub fn key_from_env() -> Key {
    match Key::from_env() {
        Ok(k) => k,
        Err((k, why)) => {
            eprintln!("warning: {KEY_ENV} {why}; running in OPEN MODE (echoes prove nothing)");
            k
        }
    }
}

/// Pick the IPv4 endpoint out of whatever `getaddrinfo` returned. Split out from
/// [`resolve`] so the preference itself is testable without DNS.
fn first_v4(addrs: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
    addrs.into_iter().find(SocketAddr::is_ipv4)
}

/// Resolve `addr` to an **IPv4** endpoint, never whatever came back first.
///
/// Everything below the socket here is IPv4: [`lok_capture`] parses IPv4 headers only, and
/// both probes bind `0.0.0.0`. So on a dual-stack sensor the order `getaddrinfo` returns is
/// not a neutral detail — RFC 6724 puts the AAAA first, and taking `.next()` handed the TCP
/// arm a V6 address it could not use. The failure was silent and one-sided:
/// `CapturingTcpProbe` returned `reachable: false`, so the RST capture never opened,
/// `measure_throughput` was skipped (it is gated on reachability), and
/// `calibrate_control_ttl` fell back to the assumed constant the per-route calibration
/// exists to replace. The run still printed `ok` — a week of rows that *cannot* contain
/// `injected_rst_at_sni` or `throttle_to_rate`, which is the false null the calibration was
/// bought to prevent. A name with no A record returns `None` and is caught by the gate in
/// [`probe_battery_with`] rather than measured half-way.
fn resolve(addr: &str) -> Option<SocketAddr> {
    first_v4(addr.to_socket_addrs().ok()?)
}

/// The peer's IPv4 address and port, for building a capture [`FlowFilter`]. `None` only when
/// the name has no IPv4 address at all — [`resolve`] already skips past any AAAA.
fn peer_v4(addr: &str) -> Option<([u8; 4], u16)> {
    match resolve(addr)? {
        SocketAddr::V4(v4) => Some((v4.ip().octets(), v4.port())),
        SocketAddr::V6(_) => None,
    }
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

    // A matching datagram arrived but its bytes were rewritten in flight — content bytes,
    // or the probe's own identifying header. The header case is only visible at all because
    // the keyed payload still names the datagram; before that it read as a *drop*, which is
    // a fabricated block on a path that delivered.
    if obs.payload_hash_mismatch || obs.echo.header_mutated {
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
/// resulting [`Observation`]. Reads the shared key from the environment; see
/// [`probe_once_with_key`] for the seam tests use.
pub fn probe_once(server: &str, count: u32) -> std::io::Result<Observation> {
    probe_once_with_key(server, count, key_from_env())
}

/// [`probe_once`] with an explicit key.
///
/// What counts as an arrival is the whole point: only an echo the far end **signed** does,
/// which is why a reflected or forged datagram leaves the marker unarrived and lands in
/// [`EchoIntegrity`] instead. A datagram whose header was rewritten in flight *is* an
/// arrival — recovered by its keyed payload — and sets the mutation signal rather than
/// silently shortening the contiguous run.
pub fn probe_once_with_key(server: &str, count: u32, key: Key) -> std::io::Result<Observation> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(server)?;
    sock.set_read_timeout(Some(Duration::from_millis(300)))?;

    let run = SentRun { key, nonce: PROBE_NONCE, session: lok_wire::new_session(), count };
    for marker in 0..count {
        sock.send(&run.request(marker))?;
    }

    let mut arrived = vec![false; count as usize];
    let mut echo = EchoIntegrity { keyed: key.is_keyed(), ..Default::default() };
    let mut payload_mutated = false;
    let mut legs: (Option<Leg>, Option<Leg>) = (None, None);
    let mut recv = [0u8; 2048];
    // The read timeout ends the loop: no more echoes are coming.
    while let Ok(n) = sock.recv(&mut recv) {
        match run.classify_echo(&recv[..n]) {
            Echo::Intact { marker } => arrived[marker as usize] = true,
            Echo::Mutated { marker, header, payload } => {
                arrived[marker as usize] = true;
                if header.is_some() {
                    echo.header_mutated = true;
                    legs.0 = header;
                }
                if payload.is_some() {
                    payload_mutated = true;
                    legs.1 = payload;
                }
            }
            Echo::Reflected { .. } => echo.reflected += 1,
            Echo::Unauthenticated => echo.unauthenticated += 1,
        }
    }

    // Which leg a rewrite happened on is a real finding (mangling is often directional) but
    // has nowhere to go in the contract yet, so it is reported to the operator, not stored.
    if echo.header_mutated || payload_mutated || echo.reflected > 0 || echo.unauthenticated > 0 {
        eprintln!(
            "echo integrity: header_mutated={:?} payload_mutated={:?} reflected={} unauthenticated={} keyed={}",
            legs.0, legs.1, echo.reflected, echo.unauthenticated, echo.keyed
        );
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
        payload_hash_mismatch: payload_mutated,
        rst: None,
        throughput_bps: None,
        expected_bps: None,
        active_probe_forwarded: false,
        echo,
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

/// A TCP socket bound to an ephemeral port *before* it connects, so the probe knows its own
/// port in advance and can scope the capture to the exact 5-tuple. `std` has no
/// bind-then-connect for TCP, hence the direct syscalls.
#[cfg(target_os = "linux")]
mod boundsock {
    use std::io;
    use std::net::SocketAddrV4;
    use std::time::Duration;

    pub struct BoundTcpSocket {
        fd: libc::c_int,
    }

    fn sockaddr_in(addr: SocketAddrV4) -> libc::sockaddr_in {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = addr.port().to_be();
        sa.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(addr.ip().octets()) };
        sa
    }

    impl BoundTcpSocket {
        /// Open a TCP socket and bind it to an ephemeral port on all interfaces.
        pub fn new() -> io::Result<Self> {
            let fd = unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let me = Self { fd };
            let sa = sockaddr_in(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
            let rc = unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(me)
        }

        /// The bound local port — the one the peer's replies (and any RST) are addressed to.
        pub fn local_port(&self) -> io::Result<u16> {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockname(self.fd, &mut sa as *mut libc::sockaddr_in as *mut libc::sockaddr, &mut len)
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(u16::from_be(sa.sin_port))
        }

        /// Connect with a deadline. Consumes the socket (the connection is only needed to
        /// learn reachability; the capture is what carries the interesting signal).
        pub fn connect_timeout(self, peer: SocketAddrV4, timeout: Duration) -> bool {
            let sa = sockaddr_in(peer);
            let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
            unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

            let rc = unsafe {
                libc::connect(
                    self.fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if rc == 0 {
                return true; // connected immediately (loopback / same host)
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
                return false; // refused outright
            }

            let mut pfd = libc::pollfd { fd: self.fd, events: libc::POLLOUT, revents: 0 };
            let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
            if unsafe { libc::poll(&mut pfd, 1, ms) } <= 0 {
                return false; // timed out or poll failed: not reachable within the deadline
            }

            // POLLOUT alone doesn't mean success — a refused connect is also writable.
            let mut err: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut err as *mut libc::c_int as *mut libc::c_void,
                    &mut len,
                )
            };
            rc == 0 && err == 0
        }
    }

    impl Drop for BoundTcpSocket {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// TCP probe that runs an `AF_PACKET` capture during the handshake and reports any RST it
/// sees *on this connection's 5-tuple*, with its TTL judged against `control_ttl`. Linux +
/// `CAP_NET_RAW`; degrades to [`PlainTcpProbe`] when the socket or capture can't be set up,
/// so a non-root run just yields `rst: None` rather than failing. The end-to-end capture
/// path is validated under the netns rig (root), not `cargo test`.
#[cfg(target_os = "linux")]
pub struct CapturingTcpProbe;

#[cfg(target_os = "linux")]
impl TcpProbe for CapturingTcpProbe {
    fn run(&self, tcp_addr: &str, control_ttl: u8) -> TcpProbeResult {
        use lok_capture::{FlowFilter, L4Proto};

        let (Some((peer_ip, peer_port)), Some(SocketAddr::V4(sa))) =
            (peer_v4(tcp_addr), resolve(tcp_addr))
        else {
            return TcpProbeResult { reachable: false, rst: None };
        };

        // Bind first: the capture filter needs our port before a single packet moves.
        let Ok(sock) = boundsock::BoundTcpSocket::new() else {
            return PlainTcpProbe.run(tcp_addr, control_ttl);
        };
        let Ok(local_port) = sock.local_port() else {
            return PlainTcpProbe.run(tcp_addr, control_ttl);
        };
        let cap = match lok_capture::AfPacketCapture::open() {
            Ok(c) => c,
            Err(_) => {
                // No CAP_NET_RAW: still measure reachability on the socket we bound.
                let reachable = sock.connect_timeout(sa, Duration::from_millis(500));
                return TcpProbeResult { reachable, rst: None };
            }
        };

        let filter = FlowFilter::inbound(peer_ip, peer_port, local_port, L4Proto::Tcp);
        let deadline = Instant::now() + Duration::from_millis(700);
        let watcher =
            std::thread::spawn(move || cap.watch_for_rst(&filter, control_ttl, deadline).ok().flatten());
        std::thread::sleep(Duration::from_millis(50)); // let the capture start listening
        let reachable = sock.connect_timeout(sa, Duration::from_millis(500));
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

/// Measure the clean-path TTL from the real peer, so the RST anomaly test compares against a
/// value observed on *this* route rather than an assumed constant. Sends one UDP datagram to
/// the server and captures the echoed reply's TTL, scoped to that datagram's own 5-tuple.
/// Linux + `CAP_NET_RAW`; falls back to [`DEFAULT_CONTROL_TTL`] when capture is unavailable
/// or no reply is seen.
#[cfg(target_os = "linux")]
fn calibrate_control_ttl(udp_addr: &str, key: Key) -> u8 {
    fn measure(udp_addr: &str, key: Key) -> Option<u8> {
        use lok_capture::{FlowFilter, L4Proto};

        let sa = resolve(udp_addr)?;
        let (peer_ip, peer_port) = peer_v4(udp_addr)?; // IPv6 calibration not modeled yet
        // Bind before capturing so the filter can name our port.
        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        let local_port = sock.local_addr().ok()?.port();
        sock.connect(sa).ok()?;
        let cap = lok_capture::AfPacketCapture::open().ok()?;
        let filter = FlowFilter::inbound(peer_ip, peer_port, local_port, L4Proto::Udp);
        // Its own session and nonce: the server only answers authenticated runs, and the
        // calibration datagram must never be counted as a marker observation.
        let run = SentRun { key, nonce: CALIBRATION_NONCE, session: lok_wire::new_session(), count: 1 };
        sock.send(&run.request(0)).ok()?;
        let deadline = Instant::now() + Duration::from_millis(400);
        cap.observe_peer_ttl(&filter, deadline).ok().flatten()
    }
    measure(udp_addr, key).unwrap_or(DEFAULT_CONTROL_TTL)
}

#[cfg(not(target_os = "linux"))]
fn calibrate_control_ttl(_udp_addr: &str, _key: Key) -> u8 {
    DEFAULT_CONTROL_TTL
}

/// The real battery: run the UDP marked-echo delta, then probe the TCP path — filling
/// `tcp_reachable` (blackout vs UDP-class kill), `rst` (on-wire `injected_rst_at_sni` via the
/// capture), `payload_hash_mismatch` (bytes rewritten in flight), and
/// `throughput_bps`/`expected_bps` (real `throttle_to_rate`). The RST anomaly is judged
/// against a control TTL calibrated per route from the real peer (falling back to
/// [`DEFAULT_CONTROL_TTL`]). Uses the default TCP probe: capturing on Linux (root), plain
/// otherwise.
pub fn probe_battery(udp_addr: &str, tcp_addr: &str, count: u32) -> std::io::Result<Observation> {
    let tcp = default_tcp_probe();
    let key = key_from_env();
    let control_ttl = calibrate_control_ttl(udp_addr, key);
    probe_battery_with(udp_addr, tcp_addr, count, tcp.as_ref(), control_ttl, key)
}

/// [`probe_battery`] with an injectable TCP probe, control TTL and key, so the RST wiring
/// can be exercised with a fake reset in tests (no root) and the real capture under the rig.
pub fn probe_battery_with(
    udp_addr: &str,
    tcp_addr: &str,
    count: u32,
    tcp: &dyn TcpProbe,
    control_ttl: u8,
    key: Key,
) -> std::io::Result<Observation> {
    // Refuse the run rather than measure half of it. With no IPv4 for a target the TCP arm
    // would report `reachable: false` and the capture would never open, which classifies as
    // a *finding* about the far end instead of an outage on this end. Erroring here exits
    // non-zero, which `deploy/run-battery.sh` files as `not_evaluated/probe_error`.
    for (arm, addr) in [("udp", udp_addr), ("tcp", tcp_addr)] {
        if resolve(addr).is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("{arm} target {addr}: no IPv4 address (the capture path is IPv4-only)"),
            ));
        }
    }

    let mut obs = probe_once_with_key(udp_addr, count, key)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// The regression that motivated this: on a dual-stack sensor RFC 6724 puts the AAAA
    /// first, and the old `.next()` handed the IPv4-only capture path a V6 address.
    /// Addresses are the RFC 3849 / RFC 5737 documentation ranges on purpose — a real sensor
    /// address in a public repo is a target list.
    #[test]
    fn resolution_skips_a_leading_v6_for_the_v4_the_capture_can_parse() {
        let addrs = vec![sa("[2001:db8::1]:47017"), sa("192.0.2.10:47017")];
        assert_eq!(first_v4(addrs.into_iter()), Some(sa("192.0.2.10:47017")));
    }

    #[test]
    fn resolution_is_none_when_there_is_no_v4_at_all() {
        let addrs = vec![sa("[2001:db8::1]:47017"), sa("[2001:db8::2]:47017")];
        assert_eq!(first_v4(addrs.into_iter()), None);
    }

    #[test]
    fn a_v4_only_answer_is_unchanged() {
        let addrs = vec![sa("127.0.0.1:47017")];
        assert_eq!(first_v4(addrs.into_iter()), Some(sa("127.0.0.1:47017")));
    }
}
