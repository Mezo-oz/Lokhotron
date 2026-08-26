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
        /// Open a capture socket for all protocols.
        pub fn open() -> io::Result<Self> {
            // socket() wants the protocol in network byte order.
            let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
            let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd })
        }

        /// Read one frame into `buf`, returning its length.
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
}
