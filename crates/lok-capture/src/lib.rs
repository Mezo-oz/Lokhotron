//! Below-the-stack capture and the RST parser.
//!
//! Three pieces:
//!  - [`parse_ipv4_tcp_rst`] / [`ipv4_src_and_ttl`] — pure parsers over an IPv4 packet.
//!  - [`FlowFilter`] — the 5-tuple a capture accepts packets for. A raw `AF_PACKET` socket
//!    sees *every* frame on the interface, so on a shared vantage (a real VPS: SSH, the
//!    host's own background traffic, a second probe run) an unfiltered match is a false
//!    positive waiting to happen — an unrelated RST from some other flow, judged against a
//!    control TTL measured on *our* route, reads as `injected_rst_at_sni`. Every accepted
//!    packet must belong to the flow being measured.
//!  - [`AfPacketCapture`] — a raw `AF_PACKET` socket (Linux, needs `CAP_NET_RAW`) that reads
//!    frames off the wire and applies the filter.

/// A TCP RST observed on the wire, reduced to the fields that distinguish forged from real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedRst {
    pub ttl: u8,
    pub ip_id: u16,
}

/// Transport protocol a [`FlowFilter`] selects on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
}

/// The flow a capture may report on: packets *inbound from* `peer:peer_port` *to* our
/// `local_port`, over `protocol`.
///
/// `local_port == 0` is a wildcard, for the case where the port genuinely isn't known in
/// advance. Prefer a real port: the probe binds its socket before opening the capture
/// precisely so it can name one here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowFilter {
    pub peer: [u8; 4],
    pub peer_port: u16,
    pub local_port: u16,
    pub protocol: L4Proto,
}

impl FlowFilter {
    /// Inbound packets of `protocol` from `peer:peer_port` to `local_port`.
    pub fn inbound(peer: [u8; 4], peer_port: u16, local_port: u16, protocol: L4Proto) -> Self {
        Self { peer, peer_port, local_port, protocol }
    }

    fn ports_ok(&self, src_port: u16, dst_port: u16) -> bool {
        src_port == self.peer_port && (self.local_port == 0 || dst_port == self.local_port)
    }
}

/// How far an observed RST's TTL may deviate from the clean control-path TTL before it is
/// judged forged. A real endpoint RST traverses the same path as the data (so its TTL is
/// close); a middlebox injecting mid-path starts from a different initial TTL.
pub const TTL_ANOMALY_THRESHOLD: u8 = 5;

/// Whether an observed RST TTL is anomalous relative to the clean control-path TTL — the
/// on-wire signature of an injected (middlebox) RST. Feeds `Observation.rst.ttl_anomaly`,
/// which the classifier turns into `injected_rst_at_sni`.
pub fn is_ttl_anomalous(rst_ttl: u8, control_ttl: u8) -> bool {
    rst_ttl.abs_diff(control_ttl) > TTL_ANOMALY_THRESHOLD
}

/// Parse an IPv4 packet's source address and TTL. Pure.
pub fn ipv4_src_and_ttl(ip_packet: &[u8]) -> Option<([u8; 4], u8)> {
    let (ipv4, _rest) = etherparse::Ipv4Header::from_slice(ip_packet).ok()?;
    Some((ipv4.source, ipv4.time_to_live))
}

/// Given a raw link-layer frame from [`AfPacketCapture`], return the IPv4 portion. Handles
/// the common `AF_PACKET` case of an Ethernet header (`0x0800` ethertype) and the already-
/// IPv4 case (cooked/loopback captures). Returns `None` for anything else.
pub fn ipv4_from_frame(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() >= 14 && frame[12] == 0x08 && frame[13] == 0x00 {
        Some(&frame[14..]) // Ethernet II + IPv4
    } else if !frame.is_empty() && (frame[0] >> 4) == 4 {
        Some(frame) // already at the IPv4 header
    } else {
        None
    }
}

/// If `ip_packet` (starting at the IPv4 header) is a TCP segment with the RST flag set,
/// return its TTL and IP-ID. Returns `None` for non-IPv4, non-TCP, or non-RST input.
/// Flow-blind — on a shared vantage use [`rst_from_flow`].
pub fn parse_ipv4_tcp_rst(ip_packet: &[u8]) -> Option<ParsedRst> {
    let (ipv4, rest) = etherparse::Ipv4Header::from_slice(ip_packet).ok()?;
    if ipv4.protocol != etherparse::IpNumber::TCP {
        return None;
    }
    let (tcp, _) = etherparse::TcpHeader::from_slice(rest).ok()?;
    if !tcp.rst {
        return None;
    }
    Some(ParsedRst {
        ttl: ipv4.time_to_live,
        ip_id: ipv4.identification,
    })
}

/// A TCP RST *belonging to `filter`'s flow*, or `None`. This is the one the probe uses: a
/// RST from any other connection on the box says nothing about the path being measured.
pub fn rst_from_flow(ip_packet: &[u8], filter: &FlowFilter) -> Option<ParsedRst> {
    if filter.protocol != L4Proto::Tcp {
        return None;
    }
    let (ipv4, rest) = etherparse::Ipv4Header::from_slice(ip_packet).ok()?;
    if ipv4.source != filter.peer || ipv4.protocol != etherparse::IpNumber::TCP {
        return None;
    }
    let (tcp, _) = etherparse::TcpHeader::from_slice(rest).ok()?;
    if !tcp.rst || !filter.ports_ok(tcp.source_port, tcp.destination_port) {
        return None;
    }
    Some(ParsedRst {
        ttl: ipv4.time_to_live,
        ip_id: ipv4.identification,
    })
}

/// The TTL of a packet *belonging to `filter`'s flow*, or `None` — the clean-path TTL the
/// RST anomaly test is calibrated against. Restricted to the flow for the same reason as
/// [`rst_from_flow`]: calibrating against a stray packet that took a different route would
/// silently mis-scale the anomaly test in either direction.
pub fn peer_ttl_from_flow(ip_packet: &[u8], filter: &FlowFilter) -> Option<u8> {
    let (ipv4, rest) = etherparse::Ipv4Header::from_slice(ip_packet).ok()?;
    if ipv4.source != filter.peer {
        return None;
    }
    let (src_port, dst_port) = match filter.protocol {
        L4Proto::Udp => {
            if ipv4.protocol != etherparse::IpNumber::UDP {
                return None;
            }
            let (udp, _) = etherparse::UdpHeader::from_slice(rest).ok()?;
            (udp.source_port, udp.destination_port)
        }
        L4Proto::Tcp => {
            if ipv4.protocol != etherparse::IpNumber::TCP {
                return None;
            }
            let (tcp, _) = etherparse::TcpHeader::from_slice(rest).ok()?;
            (tcp.source_port, tcp.destination_port)
        }
    };
    if !filter.ports_ok(src_port, dst_port) {
        return None;
    }
    Some(ipv4.time_to_live)
}

#[cfg(target_os = "linux")]
mod afpacket {
    use std::io;

    use super::FlowFilter;

    /// A raw `AF_PACKET` capture socket. Requires `CAP_NET_RAW`. Reads whole link-layer
    /// frames (Ethernet header included) via [`AfPacketCapture::recv`].
    pub struct AfPacketCapture {
        fd: libc::c_int,
    }

    impl AfPacketCapture {
        /// Open a capture socket for all protocols, with a 200 ms receive timeout so a
        /// watch loop can honor a deadline even when no packets arrive.
        pub fn open() -> io::Result<Self> {
            // socket() wants the protocol in network byte order.
            let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
            let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const libc::timeval as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            Ok(Self { fd })
        }

        /// Read one frame into `buf`, returning its length. A timeout surfaces as a
        /// `WouldBlock` error.
        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let n = unsafe {
                libc::recv(
                    self.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        /// Read frames until `deadline`, handing each one's IPv4 portion to `f` and
        /// returning the first `Some` it yields. Shared spine of the watch loops.
        fn watch<T>(
            &self,
            deadline: std::time::Instant,
            mut f: impl FnMut(&[u8]) -> Option<T>,
        ) -> io::Result<Option<T>> {
            let mut buf = [0u8; 2048];
            while std::time::Instant::now() < deadline {
                match self.recv(&mut buf) {
                    Ok(n) => {
                        if let Some(ip) = super::ipv4_from_frame(&buf[..n]) {
                            if let Some(hit) = f(ip) {
                                return Ok(Some(hit));
                            }
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                    Err(e) => return Err(e),
                }
            }
            Ok(None)
        }

        /// Watch for an inbound TCP RST *on `filter`'s flow* until `deadline`, returning
        /// the first one parsed with whether its TTL is anomalous vs `control_ttl` (the
        /// injected-RST signature). Capture is root-gated (`CAP_NET_RAW`), so this path is
        /// exercised under the calibration rig, not `cargo test`; the parsing, filtering
        /// and anomaly logic it calls are unit-tested directly.
        pub fn watch_for_rst(
            &self,
            filter: &FlowFilter,
            control_ttl: u8,
            deadline: std::time::Instant,
        ) -> io::Result<Option<(super::ParsedRst, bool)>> {
            self.watch(deadline, |ip| {
                let rst = super::rst_from_flow(ip, filter)?;
                Some((rst, super::is_ttl_anomalous(rst.ttl, control_ttl)))
            })
        }

        /// Observe the TTL of the first inbound packet *on `filter`'s flow* before
        /// `deadline` — the clean-path TTL used to calibrate the RST anomaly threshold per
        /// route. Root-gated capture; validated under the rig, the parsing it calls is
        /// unit-tested.
        pub fn observe_peer_ttl(
            &self,
            filter: &FlowFilter,
            deadline: std::time::Instant,
        ) -> io::Result<Option<u8>> {
            self.watch(deadline, |ip| super::peer_ttl_from_flow(ip, filter))
        }
    }

    impl Drop for AfPacketCapture {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use afpacket::AfPacketCapture;

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 4] = [10, 0, 0, 1];
    const US: [u8; 4] = [10, 0, 0, 2];

    /// Build an IPv4 + TCP packet (no payload) with the given flags/fields.
    fn ipv4_tcp(ttl: u8, ip_id: u16, rst: bool) -> Vec<u8> {
        ipv4_tcp_ports(ttl, ip_id, rst, 443, 55000, PEER)
    }

    fn ipv4_tcp_ports(ttl: u8, ip_id: u16, rst: bool, sport: u16, dport: u16, src: [u8; 4]) -> Vec<u8> {
        let mut ip = etherparse::Ipv4Header {
            protocol: etherparse::IpNumber::TCP,
            time_to_live: ttl,
            identification: ip_id,
            source: src,
            destination: US,
            ..Default::default()
        };
        ip.set_payload_len(20).unwrap(); // one bare TCP header

        let tcp = etherparse::TcpHeader {
            source_port: sport,
            destination_port: dport,
            rst,
            syn: !rst,
            ..Default::default()
        };

        let mut out = Vec::new();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out
    }

    fn ipv4_udp(ttl: u8, sport: u16, dport: u16, src: [u8; 4]) -> Vec<u8> {
        let payload = [0u8; 8];
        let udp = etherparse::UdpHeader {
            source_port: sport,
            destination_port: dport,
            length: (8 + payload.len()) as u16,
            checksum: 0,
        };
        let mut ip = etherparse::Ipv4Header {
            protocol: etherparse::IpNumber::UDP,
            time_to_live: ttl,
            source: src,
            destination: US,
            ..Default::default()
        };
        ip.set_payload_len(8 + payload.len()).unwrap();

        let mut out = Vec::new();
        ip.write(&mut out).unwrap();
        udp.write(&mut out).unwrap();
        out.extend_from_slice(&payload);
        out
    }

    fn tcp_filter() -> FlowFilter {
        FlowFilter::inbound(PEER, 443, 55000, L4Proto::Tcp)
    }

    #[test]
    fn parses_rst_ttl_and_ip_id() {
        let pkt = ipv4_tcp(200, 0xBEEF, true);
        let got = parse_ipv4_tcp_rst(&pkt).expect("should parse an RST");
        assert_eq!(got, ParsedRst { ttl: 200, ip_id: 0xBEEF });
    }

    #[test]
    fn ignores_non_rst_segment() {
        let syn = ipv4_tcp(64, 1, false);
        assert!(parse_ipv4_tcp_rst(&syn).is_none());
        assert!(parse_ipv4_tcp_rst(&[]).is_none());
    }

    #[test]
    fn parses_source_and_ttl() {
        let pkt = ipv4_tcp(57, 0x1234, false);
        let (src, ttl) = ipv4_src_and_ttl(&pkt).expect("parse src+ttl");
        assert_eq!(src, PEER);
        assert_eq!(ttl, 57);
    }

    #[test]
    fn ttl_anomaly_flags_forged_rst() {
        assert!(is_ttl_anomalous(200, 64)); // injected mid-path, distant initial TTL
        assert!(!is_ttl_anomalous(63, 64)); // real endpoint RST, one hop of drift
        assert!(!is_ttl_anomalous(64, 64));
    }

    #[test]
    fn strips_ethernet_and_recovers_rst() {
        let ip = ipv4_tcp(200, 0xBEEF, true);
        // Prepend a 14-byte Ethernet II header with an IPv4 ethertype.
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&ip);
        let recovered = ipv4_from_frame(&frame).expect("should strip eth");
        let rst = parse_ipv4_tcp_rst(recovered).expect("rst under eth");
        assert_eq!(rst.ttl, 200);
        assert!(is_ttl_anomalous(rst.ttl, 64));
        // A raw IPv4 packet (no eth) passes through unchanged.
        assert_eq!(ipv4_from_frame(&ip).unwrap().len(), ip.len());
    }

    #[test]
    fn flow_filter_accepts_our_rst() {
        let pkt = ipv4_tcp(200, 0xBEEF, true);
        let got = rst_from_flow(&pkt, &tcp_filter()).expect("our flow's RST");
        assert_eq!(got.ttl, 200);
    }

    /// The shared-vantage failure this filter exists to stop: an unrelated RST (another
    /// connection's, another host's) must not be reported as the measured flow's.
    #[test]
    fn flow_filter_rejects_foreign_rsts() {
        let f = tcp_filter();
        // Right peer and our port, but a different server port — a different service.
        assert!(rst_from_flow(&ipv4_tcp_ports(200, 1, true, 22, 55000, PEER), &f).is_none());
        // Right ports, wrong host.
        assert!(rst_from_flow(&ipv4_tcp_ports(200, 1, true, 443, 55000, [9, 9, 9, 9]), &f).is_none());
        // Right peer and server port, but destined for another socket on this box.
        assert!(rst_from_flow(&ipv4_tcp_ports(200, 1, true, 443, 40000, PEER), &f).is_none());
        // Right flow, but not a RST.
        assert!(rst_from_flow(&ipv4_tcp_ports(64, 1, false, 443, 55000, PEER), &f).is_none());
        // A UDP-scoped filter never yields a RST.
        let udp_filter = FlowFilter::inbound(PEER, 443, 55000, L4Proto::Udp);
        assert!(rst_from_flow(&ipv4_tcp(200, 1, true), &udp_filter).is_none());
    }

    #[test]
    fn wildcard_local_port_still_pins_the_peer() {
        let f = FlowFilter::inbound(PEER, 443, 0, L4Proto::Tcp);
        assert!(rst_from_flow(&ipv4_tcp_ports(200, 1, true, 443, 40000, PEER), &f).is_some());
        assert!(rst_from_flow(&ipv4_tcp_ports(200, 1, true, 22, 40000, PEER), &f).is_none());
    }

    #[test]
    fn ttl_calibration_only_reads_our_udp_flow() {
        let f = FlowFilter::inbound(PEER, 47017, 33333, L4Proto::Udp);
        assert_eq!(peer_ttl_from_flow(&ipv4_udp(61, 47017, 33333, PEER), &f), Some(61));
        // Same peer, different flow — would mis-scale the anomaly test if accepted.
        assert!(peer_ttl_from_flow(&ipv4_udp(61, 53, 33333, PEER), &f).is_none());
        assert!(peer_ttl_from_flow(&ipv4_udp(61, 47017, 44444, PEER), &f).is_none());
        assert!(peer_ttl_from_flow(&ipv4_udp(61, 47017, 33333, [9, 9, 9, 9]), &f).is_none());
        // Protocol must match too: a TCP packet on the same ports is not the UDP echo.
        assert!(peer_ttl_from_flow(&ipv4_tcp_ports(61, 1, false, 47017, 33333, PEER), &f).is_none());
    }
}
