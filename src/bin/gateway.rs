//! construct-transport QUIC/HTTP-3 → h2c gateway (Phase 0.5).
//!
//! Production-shaped entrypoint: terminates QUIC/H3 from clients and reverse-
//! proxies each gRPC call to an upstream h2c endpoint (envoy), bypassing
//! Traefik. Self-signed cert for now (clients pin it); real cert is a later
//! step.
//!
//! Env:
//!   QUIC_BIND      bind address          (default 0.0.0.0:443)
//!   QUIC_UPSTREAM  h2c upstream host:port(default envoy:8080)
//!   QUIC_SAN       cert SAN / client SNI (default localhost)

use std::net::SocketAddr;

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

    let bundle = tls::self_signed(vec![san.clone()])?;
    std::fs::write("server-cert.der", bundle.cert.as_ref())?;
    let server_config = tls::server_config(&bundle)?;

    let handle = proxy::serve(server_config, bind, upstream.clone()).await?;
    info!(
        addr = %handle.addr, %upstream, %san,
        "construct-transport gateway listening (h3 -> h2c); cert → server-cert.der"
    );
    handle.task.await?;
    Ok(())
}
