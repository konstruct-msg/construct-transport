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
//! `--sni <name>` overrides the SNI our probe presents (still dialing our gateway's IP) — the
//! SNI-vs-IP discriminator: if a benign SNI survives `--hold` where the real one dies, the block
//! is keyed on SNI, not destination IP. `--psk <hex>` Salamander-obfuscates our datagrams (must
//! match the gateway's `QUIC_OBF_PSK` listener) — if that survives where plain QUIC dies, hiding
//! the fact that it's QUIC defeats the block. Both apply to OUR gateway only; control stays clean.
//!
//! Usage:
//!   cargo run --bin udpcheck                          # control + quic.konstruct.cc:443
//!   cargo run --bin udpcheck -- --hold 30             # + hold each conn 30s
//!   cargo run --bin udpcheck -- --pin quic_gateway.der   # pin ours like the app
//!   cargo run --bin udpcheck -- --sni www.google.com --hold 60   # SNI-vs-IP test (no server change)
//!   cargo run --bin udpcheck -- --psk <hex> quic.konstruct.cc 8443 --hold 60  # Salamander test
//!   cargo run --bin udpcheck -- quic.example.com 443 --hold 30 --pin cert.der

use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use construct_transport::obf_socket::obfuscated_client_endpoint;
use construct_transport::salamander::{SALT_LEN, Salamander};
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

/// Decode a hex string (the Salamander PSK from `--psk`) into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(s.len().is_multiple_of(2), "hex PSK must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("invalid hex: {e}"))
        })
        .collect()
}

fn client_config(pin: Option<Vec<u8>>, obf: bool) -> Result<(quinn::ClientConfig, Arc<Verifier>)> {
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
    if obf {
        // Salamander prepends an 8-byte salt to every datagram; cap MTU discovery so the
        // obfuscated packet (QUIC || salt) stays within the path MTU (mirrors tls.rs obf cfg).
        let mut mtud = quinn::MtuDiscoveryConfig::default();
        mtud.upper_bound(1452 - SALT_LEN as u16);
        transport.mtu_discovery_config(Some(mtud));
    }
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
async fn try_quic(
    host: &str,
    port: u16,
    pin: Option<Vec<u8>>,
    hold: Duration,
    sni: Option<String>,
    psk: Option<Vec<u8>>,
) -> Probe {
    match try_quic_inner(host, port, pin, hold, sni, psk).await {
        Ok(p) => p,
        Err(e) => Probe::Fail(format!("{e}")),
    }
}

async fn try_quic_inner(
    host: &str,
    port: u16,
    pin: Option<Vec<u8>>,
    hold: Duration,
    sni: Option<String>,
    psk: Option<Vec<u8>>,
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
    let (cfg, verifier) = client_config(pin, psk.is_some())?;
    let mut endpoint = match psk {
        Some(psk) => obfuscated_client_endpoint(bind, Salamander::new(psk))
            .context("bind Salamander-obfuscated client endpoint")?,
        None => Endpoint::client(bind)?,
    };
    endpoint.set_default_client_config(cfg);

    // SNI presented in the (QUIC Initial) ClientHello. Overriding it while still dialing our
    // gateway's IP is the SNI-vs-IP discriminator: a benign SNI surviving where the real one
    // dies means the block is keyed on SNI, not destination IP.
    let server_name = sni.as_deref().unwrap_or(host);
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, endpoint.connect(addr, server_name)?)
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
    let mut sni: Option<String> = None;
    let mut psk: Option<Vec<u8>> = None;
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
            // Override the SNI our probe presents (SNI-vs-IP discriminator). Applies to `ours`.
            "--sni" => {
                sni = Some(it.next().context("--sni needs a server name")?);
            }
            // Salamander-obfuscate our datagrams with this hex PSK (must match the gateway's
            // QUIC_OBF_PSK). Applies to `ours`. Tests whether hiding QUIC defeats the block.
            "--psk" => {
                let hex = it.next().context("--psk needs a hex PSK")?;
                psk = Some(decode_hex(&hex).context("invalid --psk hex")?);
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
    if let Some(s) = &sni {
        println!("(overriding OUR SNI → \"{s}\" while dialing {ours_host}'s IP — SNI-vs-IP test)");
    }
    if psk.is_some() {
        println!("(Salamander-obfuscating OUR datagrams — tests if hiding QUIC defeats the block)");
    }
    println!();

    // Control is always plain + real SNI (public cert, never pinned). The --sni / --psk
    // overrides apply ONLY to our gateway, so control stays a clean baseline.
    print!("Control  ({CONTROL_HOST}:{CONTROL_PORT}, public HTTP/3) ... ");
    let control = try_quic(CONTROL_HOST, CONTROL_PORT, None, hold, None, None).await;
    let control_ok = report(&control, hold);

    print!("Ours     ({ours_host}:{ours_port}) ... ");
    let ours = try_quic(&ours_host, ours_port, pin, hold, sni.clone(), psk.clone()).await;
    let ours_ok = report(&ours, hold);

    let ours_throttled = matches!(ours, Probe::Throttled { .. });
    let control_throttled = matches!(control, Probe::Throttled { .. });
    let pin_mismatch = matches!(&ours, Probe::Fail(e) if e.contains("pinned cert mismatch"));
    // With --sni or --psk, `ours` is a targeting-mechanism discriminator (does hiding the SNI /
    // obfuscating QUIC defeat the block?), not a plain reachability check — interpret separately.
    let mode = if psk.is_some() {
        Some("Salamander obfuscation")
    } else if sni.is_some() {
        Some("SNI spoofing")
    } else {
        None
    };

    println!("\n{}", "─".repeat(62));
    if pin_mismatch {
        println!("VERDICT: our gateway ANSWERED, but its cert does NOT match the pinned");
        println!("         quic_gateway.der. The gateway cert was rotated and the app's");
        println!("         bundled pin is STALE → the app's QUIC fails while the network is");
        println!("         fine. Fix = re-bundle the current gateway cert. (This is our bug.)");
    } else if let Some(mode) = mode {
        match &ours {
            Probe::Ok { .. } => {
                println!("VERDICT: with {mode}, OUR gateway SURVIVED where plain QUIC to it dies.");
                println!(
                    "         → the block is DEFEATED at this layer. --sni surviving ⇒ targeting"
                );
                println!(
                    "         is by SNI (hide/spoof it). --psk surviving ⇒ hiding that it's QUIC"
                );
                println!(
                    "         works ⇒ Salamander is a viable RU transport; ship it for censored"
                );
                println!(
                    "         nets. (Compare with a plain run to the SAME port to rule out port.)"
                );
            }
            Probe::Throttled { died_after, .. } => {
                println!(
                    "VERDICT: {mode} did NOT help — our gateway still died after {died_after:?}."
                );
                println!(
                    "         → the block is DEEPER than this layer. --sni failing ⇒ NOT SNI-keyed"
                );
                println!(
                    "         (destination-IP or QUIC-fingerprint). --psk failing ⇒ even hiding"
                );
                println!(
                    "         QUIC fails ⇒ IP-level block ⇒ need fronting/relays (veil-front)."
                );
            }
            Probe::Fail(e) => {
                println!("VERDICT: with {mode}, the handshake to our gateway FAILED: {e}");
                println!("         Check the gateway serves this mode on {ours_host}:{ours_port}");
                println!("         (--psk needs the matching QUIC_OBF_PSK listener; --sni needs a");
                println!(
                    "         plain listener). Control was {}.",
                    if control_ok { "OK" } else { "also down" }
                );
            }
        }
    } else {
        match (control_ok, ours_ok) {
            (true, true) if ours_throttled && !control_throttled => {
                println!(
                    "VERDICT: the public control SURVIVED but OUR gateway was KILLED mid-connection."
                );
                println!(
                    "         QUIC/UDP works on this network — the throttle is TARGETED at our"
                );
                println!(
                    "         endpoint (by SNI or destination IP), not a generic UDP block. Re-run"
                );
                println!(
                    "         with --sni <benign> and/or --psk <key> to find which. App uses H2 meanwhile."
                );
            }
            (true, true) if control_throttled => {
                println!(
                    "VERDICT: even the public control was KILLED mid-connection — this network"
                );
                println!(
                    "         throttles ALL long-lived UDP/QUIC (generic DPI). The app falls back"
                );
                println!(
                    "         to HTTP/2 (works). Network-level, not our config. Please send this."
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
