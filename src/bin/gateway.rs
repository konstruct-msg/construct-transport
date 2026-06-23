//! construct-transport QUIC/HTTP-3 → h2c gateway (Phase 0.5).
//!
//! Production-shaped entrypoint: terminates QUIC/H3 from clients and reverse-
//! proxies each gRPC call to an upstream h2c endpoint (envoy), bypassing
//! Traefik. Self-signed cert (clients pin it); persisted across restarts so the
//! pinned DER stays stable. Real CA-issued cert is a later step.
//!
//! Env:
//!   QUIC_BIND      bind address           (default 0.0.0.0:443)
//!   QUIC_UPSTREAM  h2c upstream host:port (default envoy:8080)
//!   QUIC_SAN       cert SAN / client SNI  (default localhost)
//!   QUIC_CERT_PATH persistent cert (DER)  (default server-cert.der)
//!   QUIC_KEY_PATH  persistent key  (DER)  (default server-key.der)
//!   QUIC_OBF_PSK   Salamander PSK (hex)   (unset = plain QUIC; set = obfuscated listener)
//!
//! Mount QUIC_CERT_PATH/QUIC_KEY_PATH on a volume so the pair survives container
//! recreation; clients bundle the cert as `quic_gateway.der`. When QUIC_OBF_PSK is set,
//! every datagram is Salamander-obfuscated and only clients with the same PSK can connect.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use construct_transport::{proxy, tls};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let bind: SocketAddr = std::env::var("QUIC_BIND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "0.0.0.0:443".parse().unwrap());
    let upstream = std::env::var("QUIC_UPSTREAM").unwrap_or_else(|_| "envoy:8080".to_string());
    let san = std::env::var("QUIC_SAN").unwrap_or_else(|_| "localhost".to_string());
    let cert_path =
        PathBuf::from(std::env::var("QUIC_CERT_PATH").unwrap_or_else(|_| "server-cert.der".into()));
    let key_path =
        PathBuf::from(std::env::var("QUIC_KEY_PATH").unwrap_or_else(|_| "server-key.der".into()));

    let bundle = tls::load_or_generate(vec![san.clone()], &cert_path, &key_path)?;

    // Optional Salamander obfuscation: a hex PSK switches the listener to the DPI-evading
    // path (every datagram obfuscated; only clients with the same PSK can handshake).
    let obf_psk = std::env::var("QUIC_OBF_PSK")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| decode_hex(s.trim()))
        .transpose()?;

    let obfuscated = obf_psk.is_some();
    let handle = match obf_psk {
        Some(psk) => proxy::serve_obfuscated(&bundle, bind, upstream.clone(), psk).await?,
        None => proxy::serve(tls::server_config(&bundle)?, bind, upstream.clone()).await?,
    };
    info!(
        addr = %handle.addr, %upstream, %san, obfuscated,
        cert = %cert_path.display(), key = %key_path.display(),
        keep_alive_secs = tls::QUIC_KEEP_ALIVE_SECS, max_idle_secs = tls::QUIC_MAX_IDLE_SECS,
        "construct-transport gateway listening (h3 -> h2c); persistent cert + keep-alive"
    );
    handle.task.await?;
    Ok(())
}

/// Decode a hex string (e.g. the Salamander PSK from `QUIC_OBF_PSK`) into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(s.len() % 2 == 0, "QUIC_OBF_PSK hex must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("QUIC_OBF_PSK invalid hex: {e}"))
        })
        .collect()
}
