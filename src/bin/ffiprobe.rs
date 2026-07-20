//! `ffiprobe` — idle-survival probe over the **real FFI `RT` path**.
//!
//! Unlike `udpcheck` (bare quinn on an ad-hoc runtime — it never reproduced the app's
//! idle-death), this drives `ffi::QuicChannel::connect` + `connection_stats`, i.e. the exact
//! `RT` / `on_rt` machinery iOS and macOS-Desktop use. Connect, then sit idle and print the
//! live quinn stats every 5s. If `ping_tx` grows and `close=None` past 30s, the runtime is
//! keeping keep-alive/recv alive through idle (the 2026-07-20 current-thread fix). If it dies
//! at ~30s with `ping_tx` frozen, the idle-death reproduces here — a fast macOS repro loop.
//!
//! Usage:
//!   cargo run --bin ffiprobe -- [host] [port] [--cert path.der] [--hold secs]
//! Defaults: host quic.konstruct.cc, port 443, cert = messenger bundle, hold 60s.

use std::time::{Duration, Instant};

use construct_transport::client::QuicClient;
use construct_transport::ffi::QuicChannel;

#[tokio::main]
async fn main() {
    let mut host = "quic.konstruct.cc".to_string();
    let mut port: u16 = 443;
    let mut cert_path = format!(
        "{}/Code/construct-messenger/ConstructMessenger/quic_gateway.der",
        std::env::var("HOME").unwrap_or_default()
    );
    let mut hold_secs: u64 = 60;
    let mut direct = false;

    // Minimal positional + flag parsing. Bare `--` is ignored (shell/cargo separator).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let mut positional = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {}
            // Drive the *same h3 QuicClient* directly on this bin's main runtime, bypassing
            // the FFI `RT`/`on_rt` indirection — isolates "h3 layer" vs "RT indirection".
            "--direct" => direct = true,
            "--cert" => {
                i += 1;
                cert_path = args.get(i).cloned().unwrap_or(cert_path);
            }
            "--hold" => {
                i += 1;
                hold_secs = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(hold_secs);
            }
            other => {
                match positional {
                    0 => host = other.to_string(),
                    1 => port = other.parse().unwrap_or(port),
                    _ => {}
                }
                positional += 1;
            }
        }
        i += 1;
    }

    let cert = match std::fs::read(&cert_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("FAIL: read cert {cert_path}: {e}");
            std::process::exit(2);
        }
    };

    println!(
        "build marker: {}",
        construct_transport::ffi::transport_build_marker()
    );
    let path = if direct {
        "DIRECT (main runtime, no RT)"
    } else {
        "FFI RT path"
    };
    println!("connecting {host}:{port} (SNI={host}) via {path}, hold {hold_secs}s ...");

    let t0 = Instant::now();

    // Two ways to get a live-connection stats sampler, so we can A/B the RT indirection.
    let sample: Box<dyn Fn() -> Sampler> = if direct {
        let qc = match QuicClient::connect(&host, port, &host, cert).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("FAIL: connect: {e:#}");
                std::process::exit(2);
            }
        };
        println!("connected in {}ms", t0.elapsed().as_millis());
        Box::new(move || Sampler::Direct(qc.stats_string()))
    } else {
        let channel = match QuicChannel::connect(host.clone(), port, host.clone(), cert).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("FAIL: connect: {e}");
                std::process::exit(2);
            }
        };
        println!("connected in {}ms", t0.elapsed().as_millis());
        Box::new(move || Sampler::Ffi(channel.clone()))
    };

    // Idle loop: never send/recv application data — only sample stats, exactly like an idle
    // MessageStream parked on recv. A healthy runtime must still fire keep-alive here.
    let start = Instant::now();
    let mut last_ping = String::new();
    let mut samples = 0u32;
    let mut ping_grew = false;
    while start.elapsed() < Duration::from_secs(hold_secs) {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = match sample().resolve().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "\nVERDICT: stats failed at ~{}s: {e} — idle-death reproduced.",
                    start.elapsed().as_secs()
                );
                std::process::exit(1);
            }
        };
        let ping = s
            .split_whitespace()
            .find(|t| t.starts_with("ping_tx="))
            .unwrap_or("ping_tx=?")
            .to_string();
        if samples > 0 && ping != last_ping {
            ping_grew = true;
        }
        last_ping = ping;
        samples += 1;
        println!("[{:>3}s] {s}", start.elapsed().as_secs());
        if s.contains("close=Some") {
            eprintln!(
                "\nVERDICT: connection CLOSED during idle at ~{}s — idle-death reproduced.",
                start.elapsed().as_secs()
            );
            std::process::exit(1);
        }
    }

    if ping_grew {
        println!(
            "\nVERDICT: survived {hold_secs}s idle, ping_tx grew, close=None — drives idle keep-alive correctly."
        );
    } else {
        println!(
            "\nVERDICT: survived {hold_secs}s but ping_tx did NOT grow — keep-alive not firing (still starved)."
        );
        std::process::exit(1);
    }
}

/// Tiny enum so the idle loop can sample either a direct `QuicClient` (sync `stats_string`)
/// or an FFI `QuicChannel` (async `connection_stats` on `RT`) through one code path.
enum Sampler {
    Direct(String),
    Ffi(std::sync::Arc<QuicChannel>),
}

impl Sampler {
    async fn resolve(self) -> Result<String, String> {
        match self {
            Sampler::Direct(s) => Ok(s),
            Sampler::Ffi(ch) => ch.connection_stats().await.map_err(|e| e.to_string()),
        }
    }
}
