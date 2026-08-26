//! Below-the-stack capture and the RST parser.
//!
//! Two pieces, deliberately decoupled (wiring them together is the next increment):
//!  - [`parse_ipv4_tcp_rst`] — a pure parser: given an IPv4 packet, if it carries a TCP RST,
//!    return the RST's TTL and IP-ID. These are what let the classifier tell a *forged*
//!    (middlebox) RST from a real endpoint RST — a forged one rarely matches the clean
//!    path's TTL. Unit-testable with no privileges.
//!  - [`AfPacketCapture`] — a raw `AF_PACKET` socket (Linux, needs `CAP_NET_RAW`) that reads
//!    frames off the wire. Compiles today; not yet wired to a live probe run.

/// A TCP RST observed on the wire, reduced to the fields that distinguish forged from real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedRst {
    pub ttl: u8,
    pub ip_id: u16,
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

/// Parse an IPv4 packet's source address and TTL. Used to calibrate the clean-path TTL from
/// the real peer (so the RST anomaly test compares against a *measured* TTL, not an assumed
/// one). Pure.
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

#[cfg(target_os = "linux")]
mod afpacket {
    use std::io;

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

        /// Watch for an inbound TCP RST until `deadline`, returning the first one parsed
        /// with whether its TTL is anomalous vs `control_ttl` (the injected-RST signature).
        /// Capture is root-gated (`CAP_NET_RAW`), so this path is exercised under the
        /// calibration rig, not in `cargo test`; the parsing/anomaly logic it calls is
        /// unit-tested directly.
        pub fn watch_for_rst(
            &self,
            control_ttl: u8,
            deadline: std::time::Instant,
        ) -> io::Result<Option<(super::ParsedRst, bool)>> {
            let mut buf = [0u8; 2048];
            while std::time::Instant::now() < deadline {
                match self.recv(&mut buf) {
                    Ok(n) => {
                        if let Some(ip) = super::ipv4_from_frame(&buf[..n]) {
                            if let Some(rst) = super::parse_ipv4_tcp_rst(ip) {
                                let anomaly = super::is_ttl_anomalous(rst.ttl, control_ttl);
                                return Ok(Some((rst, anomaly)));
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

        /// Observe the TTL of the first inbound IPv4 packet from `peer` before `deadline` —
        /// the clean-path TTL used to calibrate the RST anomaly threshold per route. Root-
        /// gated capture; validated under the rig, the parsing it calls is unit-tested.
        pub fn observe_peer_ttl(
            &self,
            peer: [u8; 4],
            deadline: std::time::Instant,
        ) -> io::Result<Option<u8>> {
            let mut buf = [0u8; 2048];
            while std::time::Instant::now() < deadline {
                match self.recv(&mut buf) {
                    Ok(n) => {
                        if let Some(ip) = super::ipv4_from_frame(&buf[..n]) {
                            if let Some((src, ttl)) = super::ipv4_src_and_ttl(ip) {
                                if src == peer {
                                    return Ok(Some(ttl));
                                }
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

    /// Build an IPv4 + TCP packet (no payload) with the given flags/fields.
    fn ipv4_tcp(ttl: u8, ip_id: u16, rst: bool) -> Vec<u8> {
        let mut ip = etherparse::Ipv4Header {
            protocol: etherparse::IpNumber::TCP,
            time_to_live: ttl,
            identification: ip_id,
            source: [10, 0, 0, 1],
            destination: [10, 0, 0, 2],
            ..Default::default()
        };
        ip.set_payload_len(20).unwrap(); // one bare TCP header

        let tcp = etherparse::TcpHeader {
            source_port: 443,
            destination_port: 55000,
            rst,
            syn: !rst,
            ..Default::default()
        };

        let mut out = Vec::new();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out
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
        assert_eq!(src, [10, 0, 0, 1]);
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
}
