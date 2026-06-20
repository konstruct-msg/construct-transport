//! Standalone runner for the Phase 0 echo server.
//!
//! Useful for the second half of Phase 0 validation — pointing a real iOS
//! device at the laptop. Writes the self-signed cert to `server-cert.der` so a
//! client can be told to trust it.
//!
//! Usage:
//!   cargo run                       # listens on 0.0.0.0:4433
//!   cargo run -- 0.0.0.0:443        # custom bind

use std::net::SocketAddr;

use anyhow::Result;
use construct_transport::{echo_server, tls};
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

    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    std::fs::write("server-cert.der", bundle.cert.as_ref())?;

    let server_config = tls::server_config(&bundle)?;
    let bind: SocketAddr = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "0.0.0.0:4433".parse().unwrap());

    let server = echo_server::spawn_echo_server(server_config, bind).await?;
    info!(addr = %server.addr, "construct-transport echo server (quinn+h3) listening; cert → server-cert.der");
    server.task.await?;
    Ok(())
}
