//! Minimal native quinn+h3 gRPC echo server (Phase 0).
//!
//! This is the piece nobody had: a server that terminates QUIC/HTTP-3 natively
//! and behaves like a gRPC bidi handler. For every request it:
//!
//!   1. sends `200` response HEADERS *immediately* (before reading any client
//!      data) — this is the exact behaviour that silent-failed through Traefik;
//!   2. echoes every inbound gRPC frame back out, interleaved, while the stream
//!      stays open in both directions (true bidi);
//!   3. sends `grpc-status: 0` trailers when the client half-closes.
//!
//! It doubles as the reference for what the **backend** must provide: a native
//! H3 gРС endpoint (or an h3→h2c gateway) that does the above, bypassing the
//! Traefik QUIC↔h2c bridge.

use std::net::SocketAddr;

use anyhow::Result;
use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, Response};
use quinn::Endpoint;
use tracing::{debug, warn};

/// A running echo server: its bound address, the endpoint, and the accept task.
pub struct ServerHandle {
    pub addr: SocketAddr,
    pub endpoint: Endpoint,
    pub task: tokio::task::JoinHandle<()>,
}

/// Bind a quinn endpoint with `server_config` and start accepting H3 connections.
pub async fn spawn_echo_server(
    server_config: quinn::ServerConfig,
    bind: SocketAddr,
) -> Result<ServerHandle> {
    spawn_echo_on_endpoint(Endpoint::server(server_config, bind)?)
}

/// Run the echo accept-loop on a pre-built endpoint — lets callers inject a custom
/// `AsyncUdpSocket` (e.g. the Salamander-obfuscated socket) before handing it over.
pub fn spawn_echo_on_endpoint(endpoint: Endpoint) -> Result<ServerHandle> {
    let addr = endpoint.local_addr()?;
    let accept_ep = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = accept_ep.accept().await {
            tokio::spawn(async move {
                if let Err(e) = handle_conn(incoming).await {
                    warn!("connection ended: {e:#}");
                }
            });
        }
    });
    Ok(ServerHandle {
        addr,
        endpoint,
        task,
    })
}

async fn handle_conn(incoming: quinn::Incoming) -> Result<()> {
    let conn = incoming.await?;
    debug!(rtt = ?conn.rtt(), "QUIC connection accepted");
    let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

    // Sequential request handling per connection is fine for the spike.
    // h3 0.0.8: accept() yields a RequestResolver; resolve it for (req, stream).
    while let Some(resolver) = h3.accept().await? {
        let (req, mut stream) = resolver.resolve_request().await?;
        debug!(path = %req.uri().path(), "request accepted");

        // 1. Headers-first: the bidi gate.
        let resp = Response::builder()
            .status(200)
            .header("content-type", "application/grpc+proto")
            .body(())?;
        stream.send_response(resp).await?;

        // 2. Echo every inbound gRPC frame back, interleaved.
        while let Some(mut chunk) = stream.recv_data().await? {
            let data: Bytes = chunk.copy_to_bytes(chunk.remaining());
            stream.send_data(data).await?;
        }

        // 3. Client half-closed → send OK trailers and finish.
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        stream.send_trailers(trailers).await?;
        let _ = stream.finish().await;
    }
    Ok(())
}
