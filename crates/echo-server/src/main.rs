//! `echo-server <addr> [drop_after_marker]`
//!
//! With no second arg, echoes everything (a real server). With a number `k`, drops markers
//! `>= k` — fault-emulation for the calibration harness ONLY.

use std::net::{TcpListener, UdpSocket};
use std::process::ExitCode;

use echo_server::{serve, serve_tcp, DropPolicy};

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

    eprintln!("echo-server on {addr} (udp{}) policy={policy:?}", if serve_tcp_side { "+tcp" } else { "" });
    if let Err(e) = serve(sock, policy) {
        eprintln!("serve: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
