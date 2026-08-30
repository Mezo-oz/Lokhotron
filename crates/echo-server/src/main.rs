//! `echo-server <addr> [fault]`
//!
//! With no second arg, echoes everything (a real server). `fault` is calibration-only
//! fault-emulation: a number `k` drops markers `>= k`; `reflect` bounces requests back
//! unsigned, impersonating an on-path middlebox faking delivery.
//!
//! The shared secret comes from `LOK_PROBE_KEY` (64 hex chars) and must match the sensor's.
//! Without it the server runs in open mode — it still works, but its echoes prove nothing
//! about who sent them.

use std::net::{TcpListener, UdpSocket};
use std::process::ExitCode;

use echo_server::{serve, serve_tcp, FaultPolicy};
use lok_wire::{Key, KEY_ENV};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:47017".to_string());
    let policy = match args.get(2).map(|s| s.as_str()) {
        None => FaultPolicy::None,
        Some("reflect") => FaultPolicy::ReflectVerbatim,
        Some(k) => match k.parse::<u32>() {
            Ok(k) => FaultPolicy::DropFromMarker(k),
            Err(_) => {
                eprintln!("fault must be a u32 marker or the word 'reflect'");
                return ExitCode::from(2);
            }
        },
    };

    let key = match Key::from_env() {
        Ok(k) => k,
        Err((k, why)) => {
            eprintln!("warning: {KEY_ENV} {why}; running in OPEN MODE (echoes prove nothing)");
            k
        }
    };

    let sock = match UdpSocket::bind(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bind udp {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    // TCP byte-echo on the same address (separate namespace) for reachability + throughput.
    // Set LOK_NO_TCP=1 to leave TCP unserved — used by the rig's injected-RST case, where a
    // refused connect is what produces the RST.
    let serve_tcp_side = std::env::var_os("LOK_NO_TCP").is_none();
    if serve_tcp_side {
        let tcp = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("bind tcp {addr}: {e}");
                return ExitCode::FAILURE;
            }
        };
        std::thread::spawn(move || {
            if let Err(e) = serve_tcp(tcp) {
                eprintln!("serve_tcp: {e}");
            }
        });
    }

    eprintln!(
        "echo-server on {addr} (udp{}) policy={policy:?} keyed={}",
        if serve_tcp_side { "+tcp" } else { "" },
        key.is_keyed()
    );
    if let Err(e) = serve(sock, policy, key) {
        eprintln!("serve: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
