//! `echo-server <addr> [drop_after_marker]`
//!
//! With no second arg, echoes everything (a real server). With a number `k`, drops markers
//! `>= k` — fault-emulation for the calibration harness ONLY.

use std::net::UdpSocket;
use std::process::ExitCode;

use echo_server::{serve, DropPolicy};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:47017".to_string());
    let policy = match args.get(2).map(|s| s.parse::<u32>()) {
        None => DropPolicy::None,
        Some(Ok(k)) => DropPolicy::DropFromMarker(k),
        Some(Err(_)) => {
            eprintln!("drop_after_marker must be a u32");
            return ExitCode::from(2);
        }
    };

    let sock = match UdpSocket::bind(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("echo-server on {addr} policy={policy:?}");
    if let Err(e) = serve(sock, policy) {
        eprintln!("serve: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
