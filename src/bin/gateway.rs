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
//!
//! Mount QUIC_CERT_PATH/QUIC_KEY_PATH on a volume so the pair survives container
//! recreation; clients bundle the cert as `quic_gateway.der`.

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
    let server_config = tls::server_config(&bundle)?;

    let handle = proxy::serve(server_config, bind, upstream.clone()).await?;
    info!(
        addr = %handle.addr, %upstream, %san,
        cert = %cert_path.display(), key = %key_path.display(),
        "construct-transport gateway listening (h3 -> h2c); persistent cert"
    );
    handle.task.await?;
    Ok(())
}
