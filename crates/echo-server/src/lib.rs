//! Marked-echo UDP server. Each datagram is `[nonce: u32 BE][marker: u32 BE]` followed by
//! optional payload; the server echoes it back verbatim. This is the non-RU end of the
//! UDP delta: what comes back is the "arrived" signal for that marker.
//!
//! [`DropPolicy`] is **fault-emulation for calibration only** — it lets the local
//! netns/loopback harness inject a known `silent_drop_from_segment` so the classifier can
//! be checked against ground truth. It has no place in a real deployment.

use std::net::UdpSocket;

/// Fault-emulation policy. Real servers always run [`DropPolicy::None`].
#[derive(Debug, Clone, Copy)]
pub enum DropPolicy {
    /// Echo everything.
    None,
    /// Silently drop any datagram whose marker is `>= k` (emulates a drop from segment k).
    DropFromMarker(u32),
}

impl DropPolicy {
    fn should_echo(self, marker: u32) -> bool {
        match self {
            DropPolicy::None => true,
            DropPolicy::DropFromMarker(k) => marker < k,
        }
    }
}

/// The minimum datagram length: nonce + marker.
pub const HEADER_LEN: usize = 8;

/// Parse the marker out of a datagram, if it is long enough.
pub fn marker_of(datagram: &[u8]) -> Option<u32> {
    if datagram.len() < HEADER_LEN {
        return None;
    }
    Some(u32::from_be_bytes(datagram[4..8].try_into().unwrap()))
}

/// Serve marked-echo on an already-bound socket until an error occurs. Takes ownership so
/// tests can bind to port 0, read the assigned address, then hand the socket over.
pub fn serve(sock: UdpSocket, policy: DropPolicy) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = sock.recv_from(&mut buf)?;
        let datagram = &buf[..n];
        let Some(marker) = marker_of(datagram) else {
            continue; // too short to be one of ours
        };
        if policy.should_echo(marker) {
            sock.send_to(datagram, peer)?;
        }
    }
}
