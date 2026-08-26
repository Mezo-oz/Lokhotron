//! `probe <server_addr> [count]` — runs one UDP battery and prints the verdict as JSON.
//!
//! e.g. against an echo server dropping markers >= 4:
//!   probe 127.0.0.1:47017 8  ->  {"kind":"silent_drop_from_segment","n":4}

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let server = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:47017".to_string());
    let count: u32 = match args.get(2).map(|s| s.parse::<u32>()) {
        None => 8,
        Some(Ok(c)) => c,
        Some(Err(_)) => {
            eprintln!("count must be a u32");
            return ExitCode::from(2);
        }
    };

    // Full battery: UDP marked-echo delta + real TCP reachability/throughput against the
    // same address (UDP and TCP are separate namespaces).
    match probe::probe_battery(&server, &server, count) {
        Ok(obs) => {
            let verdict = probe::classify(&obs);
            println!("{}", serde_json::to_string(&verdict).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("probe {server}: {e}");
            ExitCode::FAILURE
        }
    }
}
