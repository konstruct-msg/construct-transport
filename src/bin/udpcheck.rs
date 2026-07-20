//! UDP/QUIC reachability check for testers — network-vs-config diagnostic.
//!
//! Runs a QUIC (HTTP/3) handshake to a KNOWN-GOOD public endpoint AND to our
//! gateway, then prints a verdict that separates the two causes of "QUIC doesn't
//! work":
//!
//!   * control fails            → this network throttles/blocks UDP/443 (QUIC).
//!     Network-level censorship — the app falls back
//!     to HTTP/2 (which works). NOT our bug.
//!   * control OK, ours fails   → UDP/443 works on this network but our gateway
//!     didn't answer → our config/server, or a block
//!     targeted at our SNI. Please send us the output.
//!   * both OK                  → QUIC/UDP reaches us end-to-end on this network.
//!
//! `--hold <secs>` keeps each connection open (with keep-alive) after the
//! handshake and reports if the network KILLS it — reproduces the app's real
//! failure on censored networks (handshake OK, then the sustained MessageStream
//! is throttled to death: `recv_data: Timeout`).
//!
//! `--pin <cert.der>` validates our gateway against a specific pinned cert,
//! exactly like the app does (`quic_gateway.der`). Use it to detect a STALE pin:
//! plain run OK + `--pin` FAIL ⇒ the gateway's cert rotated and the app's bundled
//! `.der` is out of date (our bug). Either way the tool prints the live leaf
//! cert's SHA-256 so it can be compared to the bundled one.
//!
//! Server-cert validation is otherwise SKIPPED (reachability only). For a full
//! validated bidi roundtrip use the `probe` bin (needs the server-cert.der).
//!
//! Usage:
//!   cargo run --bin udpcheck                          # control + quic.konstruct.cc:443
//!   cargo run --bin udpcheck -- --hold 30             # + hold each conn 30s
//!   cargo run --bin udpcheck -- --pin quic_gateway.der   # pin ours like the app
//!   cargo run --bin udpcheck -- quic.example.com 443 --hold 30 --pin cert.der

use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use quinn::Endpoint;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

const CONTROL_HOST: &str = "cloudflare-quic.com";
const CONTROL_PORT: u16 = 443;
const DEFAULT_OURS_HOST: &str = "quic.konstruct.cc";
const DEFAULT_OURS_PORT: u16 = 443;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

fn hex_fp(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Reachability verifier. Captures the server's leaf cert SHA-256 (for the
/// fingerprint print) and, if `pin` is set, enforces it exactly like the app —
/// otherwise accepts any cert (the tool never carries traffic).
#[derive(Debug)]
struct Verifier {
    provider: Arc<CryptoProvider>,
    pin: Option<Vec<u8>>,
    seen_fp: Mutex<Option<String>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        *self.seen_fp.lock().unwrap() = Some(hex_fp(digest.as_ref()));
        if let Some(pin) = &self.pin
            && end_entity.as_ref() != pin.as_slice()
        {
            return Err(rustls::Error::General(
                "pinned cert mismatch — gateway cert differs from the bundled quic_gateway.der"
                    .into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(pin: Option<Vec<u8>>) -> Result<(quinn::ClientConfig, Arc<Verifier>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Verifier {
        provider: provider.clone(),
        pin,
        seen_fp: Mutex::new(None),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    // HTTP/3 ALPN so a real h3 endpoint (Cloudflare) accepts the handshake.
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .context("build QUIC client config")?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(qcc));

    // Keep the connection alive during --hold so a drop means the *network* killed
    // it, not our own idle timeout. Mirrors the app's relaxed keep-alive/idle.
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    cfg.transport_config(Arc::new(transport));
    Ok((cfg, verifier))
}

enum Probe {
    /// Handshake failed — no QUIC/UDP round-trip (or a pin mismatch).
    Fail(String),
    /// Handshake OK (and, if held, survived the whole hold window).
    Ok { rtt: Duration, fp: Option<String> },
    /// Handshake OK but the connection was killed during the hold window —
    /// the sustained-stream throttle the app hits.
    Throttled {
        rtt: Duration,
        died_after: Duration,
        reason: String,
        fp: Option<String>,
    },
}

/// One QUIC handshake to `host:port`; if `hold > 0`, keep it open that long and
/// watch for a network-induced drop.
async fn try_quic(host: &str, port: u16, pin: Option<Vec<u8>>, hold: Duration) -> Probe {
    match try_quic_inner(host, port, pin, hold).await {
        Ok(p) => p,
        Err(e) => Probe::Fail(format!("{e}")),
    }
}

async fn try_quic_inner(
    host: &str,
    port: u16,
    pin: Option<Vec<u8>>,
    hold: Duration,
) -> Result<Probe> {
    let addr = format!("{host}:{port}")
        .to_socket_addrs()
        .with_context(|| format!("DNS resolve {host}:{port}"))?
        .next()
        .with_context(|| format!("no address for {host}:{port}"))?;

    // Bind the local socket to the SAME address family the target resolved to.
    // Binding 0.0.0.0 (IPv4) while DNS handed us an IPv6 address sends packets
    // nowhere → a silent handshake timeout that looks like a UDP block but isn't.
    let bind: std::net::SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let (cfg, verifier) = client_config(pin)?;
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(cfg);

    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, endpoint.connect(addr, host)?)
        .await
        .context("QUIC handshake timed out — UDP/443 is filtered or throttled on this path")??;
    let rtt = conn.rtt();
    let fp = verifier.seen_fp.lock().unwrap().clone();

    if !hold.is_zero() {
        let start = Instant::now();
        loop {
            if let Some(reason) = conn.close_reason() {
                let died_after = start.elapsed();
                conn.close(0u32.into(), b"udpcheck done");
                endpoint.wait_idle().await;
                return Ok(Probe::Throttled {
                    rtt,
                    died_after,
                    reason: format!("{reason}"),
                    fp,
                });
            }
            if start.elapsed() >= hold {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    conn.close(0u32.into(), b"udpcheck done");
    endpoint.wait_idle().await;
    Ok(Probe::Ok { rtt, fp })
}

/// Print one endpoint's result; returns true if the handshake succeeded.
fn report(probe: &Probe, hold: Duration) -> bool {
    match probe {
        Probe::Ok { rtt, fp } => {
            if hold.is_zero() {
                println!("OK  (QUIC handshake succeeded, rtt {rtt:?})");
            } else {
                println!("OK  (handshake rtt {rtt:?}, connection survived {hold:?})");
            }
            if let Some(fp) = fp {
                println!("         └─ server cert SHA-256: {fp}");
            }
            true
        }
        Probe::Throttled {
            rtt,
            died_after,
            reason,
            fp,
        } => {
            println!(
                "THROTTLED  (handshake OK rtt {rtt:?}, but connection DIED after {died_after:?})"
            );
            println!("         └─ {reason}");
            if let Some(fp) = fp {
                println!("         └─ server cert SHA-256: {fp}");
            }
            true
        }
        Probe::Fail(e) => {
            println!("FAIL");
            println!("         └─ {e}");
            false
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Parse `[host] [port]` positionals + optional `--hold <secs>` and `--pin <cert.der>`.
    let mut hold_secs: u64 = 0;
    let mut pin_path: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--hold" => {
                hold_secs = it
                    .next()
                    .context("--hold needs a number of seconds")?
                    .parse()
                    .context("invalid --hold value")?;
            }
            "--pin" => {
                pin_path = Some(it.next().context("--pin needs a path to a cert.der")?);
            }
            // Standard end-of-options separator; harmless when run directly as
            // `udpcheck -- --hold 30`. Never mistake it for the host.
            "--" => continue,
            _ => positional.push(a),
        }
    }
    let ours_host = positional
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_OURS_HOST.to_string());
    let ours_port: u16 = match positional.get(1) {
        Some(p) => p.parse().context("invalid port")?,
        None => DEFAULT_OURS_PORT,
    };
    let hold = Duration::from_secs(hold_secs);
    let pin: Option<Vec<u8>> = match &pin_path {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("read pin cert {p}"))?),
        None => None,
    };

    println!("UDP/QUIC reachability check");
    if !hold.is_zero() {
        println!("(holding each connection {hold:?} to catch sustained-stream throttling)");
    }
    if let Some(p) = &pin_path {
        println!("(pinning our gateway to {p}, exactly like the app)");
    }
    println!();

    // Control is never pinned (public cert); ours is pinned iff --pin was given.
    print!("Control  ({CONTROL_HOST}:{CONTROL_PORT}, public HTTP/3) ... ");
    let control = try_quic(CONTROL_HOST, CONTROL_PORT, None, hold).await;
    let control_ok = report(&control, hold);

    print!("Ours     ({ours_host}:{ours_port}) ... ");
    let ours = try_quic(&ours_host, ours_port, pin, hold).await;
    let ours_ok = report(&ours, hold);

    let ours_throttled = matches!(ours, Probe::Throttled { .. });
    let control_throttled = matches!(control, Probe::Throttled { .. });
    let pin_mismatch = matches!(&ours, Probe::Fail(e) if e.contains("pinned cert mismatch"));

    println!("\n{}", "─".repeat(62));
    if pin_mismatch {
        println!("VERDICT: our gateway ANSWERED, but its cert does NOT match the pinned");
        println!("         quic_gateway.der. The gateway cert was rotated and the app's");
        println!("         bundled pin is STALE → the app's QUIC fails while the network is");
        println!("         fine. Fix = re-bundle the current gateway cert. (This is our bug.)");
    } else {
        match (control_ok, ours_ok) {
            (true, true) if ours_throttled || control_throttled => {
                println!(
                    "VERDICT: QUIC HANDSHAKES succeed but a sustained connection gets KILLED on"
                );
                println!(
                    "         this network — the classic DPI throttle of long-lived UDP/QUIC."
                );
                println!(
                    "         This is why the app's message stream drops mid-session and falls"
                );
                println!(
                    "         back to HTTP/2. Network-level, not our config. Please send this."
                );
            }
            (true, true) => {
                println!("VERDICT: QUIC/UDP works end-to-end to our gateway on this network.");
                println!(
                    "         If the app still uses H2 here, capture app logs — not a UDP block."
                );
            }
            (true, false) => {
                println!("VERDICT: UDP/443 works on this network (public QUIC OK) but our gateway");
                println!("         did NOT answer. This points at OUR config/server (or a block");
                println!(
                    "         targeted at our SNI), not your network. Please send this output."
                );
            }
            (false, false) => {
                println!(
                    "VERDICT: UDP/443 (QUIC) is blocked or throttled on THIS network — even a"
                );
                println!(
                    "         major public endpoint failed. This is network-level censorship,"
                );
                println!(
                    "         not our config. The app automatically falls back to HTTP/2 (works)."
                );
            }
            (false, true) => {
                println!("VERDICT: Our gateway answered but the public control did not — unusual.");
                println!(
                    "         Likely a transient issue reaching {CONTROL_HOST}; re-run to confirm."
                );
            }
        }
    }
    println!("{}", "─".repeat(62));

    // Non-zero exit when UDP works publicly but our endpoint is the odd one out
    // (includes a stale-pin mismatch).
    if control_ok && !ours_ok {
        std::process::exit(2);
    }
    Ok(())
}
