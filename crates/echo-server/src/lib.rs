//! Marked-echo UDP server — the non-RU end of the delta.
//!
//! Datagrams are the keyed v2 format defined in `lok-wire`. The server does two things
//! that matter, and both are about not lying to the sensor:
//!
//! - **It admits only authenticated runs.** A datagram whose session tag doesn't verify is
//!   discarded unanswered. Without that check this is an open UDP echo on a public IP —
//!   a reflector, an abuse report, and a provider null-route that would arrive at the
//!   sensor looking exactly like a censorship finding.
//! - **It signs what it received, not what it should have received.** The response tag
//!   covers the header and payload as they actually arrived, which is what lets the sensor
//!   tell a forward-leg rewrite from a return-leg one (see `lok-wire`'s `classify_echo`).
//!
//! [`FaultPolicy`] is **fault-emulation for calibration only** — it lets the local
//! netns/loopback harness inject a known verdict so the classifier can be checked against
//! ground truth. It has no place in a real deployment.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};

use lok_wire::{build_response, is_authentic_request, parse, Key, DATAGRAM_LEN};

/// Fault-emulation policy. Real servers always run [`FaultPolicy::None`].
#[derive(Debug, Clone, Copy)]
pub enum FaultPolicy {
    /// Echo everything (correctly signed).
    None,
    /// Silently drop any datagram whose marker is `>= k` (emulates a drop from segment k).
    DropFromMarker(u32),
    /// Bounce the request back byte for byte, with no response tag — impersonating the
    /// server the way an on-path middlebox would if it wanted a dropped path to read as
    /// healthy. The sensor must refuse to score these as arrivals.
    ReflectVerbatim,
}

impl FaultPolicy {
    fn should_echo(self, marker: u32) -> bool {
        match self {
            FaultPolicy::None | FaultPolicy::ReflectVerbatim => true,
            FaultPolicy::DropFromMarker(k) => marker < k,
        }
    }
}

/// Serve marked-echo on an already-bound socket until an error occurs. Takes ownership so
/// tests can bind to port 0, read the assigned address, then hand the socket over.
///
/// `key` must be the same secret the sensor runs with; see `deploy/DEPLOY.md`.
pub fn serve(sock: UdpSocket, policy: FaultPolicy, key: Key) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = sock.recv_from(&mut buf)?;
        if n != DATAGRAM_LEN {
            continue; // not one of ours
        }
        let datagram: [u8; DATAGRAM_LEN] = buf[..DATAGRAM_LEN].try_into().unwrap();
        let Some(parsed) = parse(&datagram) else {
            continue;
        };
        // The admission check. Everything past here is a datagram from a run holding the
        // key, so answering it cannot be turned into a reflection attack on a third party.
        if !is_authentic_request(&key, &parsed) {
            continue;
        }
        if !policy.should_echo(parsed.header.marker) {
            continue;
        }
        let reply = match policy {
            FaultPolicy::ReflectVerbatim => datagram,
            _ => build_response(&key, &datagram),
        };
        sock.send_to(&reply, peer)?;
    }
}

/// Serve a TCP byte-echo on an already-bound listener until an error occurs. This is the
/// far end for the probe's `tcp_reachable` check and its bulk-throughput measurement: a
/// successful connect proves the TCP path is up; echoing bytes lets the probe time the
/// round trip. Each connection is handled on its own thread (sync model, no async runtime).
pub fn serve_tcp(listener: TcpListener) -> std::io::Result<()> {
    for stream in listener.incoming() {
        let mut stream = stream?;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break, // peer closed
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
    Ok(())
}
