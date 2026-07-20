//! UniFFI surface (Phase 1) — the transport-only client exposed to Swift.
//!
//! Mirrors the `client` module but in UniFFI-friendly shapes:
//!   * one `QuicChannel` per QUIC/H3 connection,
//!   * `open_stream` returns one `QuicStream` that internally holds the split
//!     send/recv halves behind separate mutexes — so a Swift task sending and a
//!     Swift task receiving never block each other (full-duplex `MessageStream`),
//!   * async methods (`async_runtime = "tokio"`), `Result` → `TransportError`.
//!
//! The Swift gRPC-swift `ClientTransport` adapter sits directly on this.
//!
//! ## Why every operation runs on a dedicated runtime (`RT`)
//!
//! quinn drives a connection's I/O — including the keep-alive timer, outgoing-packet
//! flushing, and incoming-packet processing — from background tasks (`tokio::spawn`) owned
//! by the endpoint driver. Those tasks only make progress while a tokio runtime with live
//! worker threads is polling them. UniFFI's `async_runtime = "tokio"` only drives the
//! *specific exported future* the foreign side is awaiting; it does NOT keep spawned
//! background tasks running between calls. So on iOS the connection worked for the first
//! exchange (while `connect`/`recv` were actively polled) and then froze: a parked
//! `recv_message` left the endpoint driver starved, so no keep-alive PINGs went out, queued
//! sends never flushed, and incoming packets were never processed — the connection idle-timed
//! out at ~30s (client "open timed out" / gateway "h3 recv_data: Timeout"). Mirrors the
//! construct-engine fix: own a multi-thread runtime and run all QUIC work on it so the
//! drivers always have worker threads. (Verified via device + gateway debug logs 2026-06-23.)

use std::sync::{Arc, LazyLock};

use tokio::sync::Mutex;

use crate::client::{QuicClient, QuicRecvStream, QuicSendStream};

/// Dedicated multi-thread runtime that owns all QUIC/h3 work, so quinn's endpoint/connection
/// drivers (keep-alive, flush, recv) always have live worker threads — independent of how
/// UniFFI polls the exported futures. See module docs.
static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("construct-transport")
        .enable_all()
        .build()
        .expect("build construct-transport tokio runtime")
});

/// Run `fut` on the dedicated runtime and await its result on the caller's (UniFFI) runtime.
async fn on_rt<F, T>(fut: F) -> Result<T, TransportError>
where
    F: std::future::Future<Output = Result<T, TransportError>> + Send + 'static,
    T: Send + 'static,
{
    RT.spawn(fut)
        .await
        .map_err(|e| TransportError::Transport(format!("transport runtime join: {e}")))?
}

/// Error surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TransportError {
    #[error("{0}")]
    Transport(String),
}

fn err(e: anyhow::Error) -> TransportError {
    TransportError::Transport(format!("{e:#}"))
}

/// Build/behaviour marker so the iOS app log can confirm exactly which transport binary
/// (.a) is actually linked — Xcode silently reuses a cached static lib, which has masked
/// several fixes. Bump on changes that need on-device verification.
#[uniffi::export]
pub fn transport_build_marker() -> String {
    "quic-plain-relaxed-keepalive-2026-06-24".to_string()
}

/// A request/response header pair (e.g. `authorization`, `grpc-status`).
/// Named `GrpcHeader` (not `Metadata`) to avoid colliding with gRPC-swift's
/// `Metadata` type in the app module.
#[derive(uniffi::Record)]
pub struct GrpcHeader {
    pub key: String,
    pub value: String,
}

/// One QUIC/HTTP-3 connection to a gateway. Open streams from it; they are
/// multiplexed over the single connection.
#[derive(uniffi::Object)]
pub struct QuicChannel {
    inner: Arc<QuicClient>,
}

#[uniffi::export(async_runtime = "tokio")]
impl QuicChannel {
    /// Connect to `host:port`, pinning the gateway's `trust_cert` (DER).
    /// `server_name` is the TLS SNI and must match the cert SAN.
    #[uniffi::constructor]
    pub async fn connect(
        host: String,
        port: u16,
        server_name: String,
        trust_cert: Vec<u8>,
    ) -> Result<Arc<Self>, TransportError> {
        // Connect (and thus spawn quinn's endpoint + h3 drivers) ON `RT` so they run on its
        // worker threads for the connection's whole life — not just during this call.
        let inner = on_rt(async move {
            QuicClient::connect(&host, port, &server_name, trust_cert)
                .await
                .map_err(err)
        })
        .await?;
        Ok(Arc::new(Self {
            inner: Arc::new(inner),
        }))
    }

    /// Like [`connect`](Self::connect) but Salamander-obfuscates every datagram with `psk`
    /// (the DPI-evading path). The gateway must apply the same PSK; `psk` is provisioned
    /// out-of-band via the veil-ticket mechanism, never hardcoded.
    #[uniffi::constructor]
    pub async fn connect_obfuscated(
        host: String,
        port: u16,
        server_name: String,
        trust_cert: Vec<u8>,
        psk: Vec<u8>,
    ) -> Result<Arc<Self>, TransportError> {
        let inner = on_rt(async move {
            QuicClient::connect_obfuscated(&host, port, &server_name, trust_cert, psk)
                .await
                .map_err(err)
        })
        .await?;
        Ok(Arc::new(Self {
            inner: Arc::new(inner),
        }))
    }

    /// Open a gRPC call on `path` (`/package.Service/Method`) with extra request
    /// `metadata` headers.
    pub async fn open_stream(
        &self,
        path: String,
        metadata: Vec<GrpcHeader>,
    ) -> Result<Arc<QuicStream>, TransportError> {
        let md: Vec<(String, String)> = metadata.into_iter().map(|m| (m.key, m.value)).collect();
        let client = self.inner.clone();
        let stream =
            on_rt(async move { client.open_stream(&path, &md).await.map_err(err) }).await?;
        let (send, recv) = stream.split();
        Ok(Arc::new(QuicStream {
            send: Arc::new(Mutex::new(send)),
            recv: Arc::new(Mutex::new(recv)),
        }))
    }

    /// Diagnostic: live quinn connection stats (tx/rx datagrams, PING frames sent, RTT,
    /// close reason). Runs on `RT`, so it also proves the dedicated runtime is responsive.
    /// `ping_tx` not growing over time ⇒ keep-alive isn't firing.
    pub async fn connection_stats(&self) -> Result<String, TransportError> {
        let client = self.inner.clone();
        on_rt(async move { Ok(client.stats_string()) }).await
    }
}

/// One gRPC call. Send and receive halves are independently locked, so a Swift
/// sender task and receiver task run concurrently. Every operation runs on `RT`.
#[derive(uniffi::Object)]
pub struct QuicStream {
    send: Arc<Mutex<QuicSendStream>>,
    recv: Arc<Mutex<QuicRecvStream>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl QuicStream {
    /// Send one gRPC message.
    pub async fn send_message(&self, message: Vec<u8>) -> Result<(), TransportError> {
        let send = self.send.clone();
        on_rt(async move { send.lock().await.send_message(&message).await.map_err(err) }).await
    }

    /// Half-close the client send side.
    pub async fn finish(&self) -> Result<(), TransportError> {
        let send = self.send.clone();
        on_rt(async move { send.lock().await.finish().await.map_err(err) }).await
    }

    /// Await the response headers; returns the HTTP status code.
    pub async fn recv_response(&self) -> Result<u16, TransportError> {
        let recv = self.recv.clone();
        on_rt(async move { recv.lock().await.recv_response().await.map_err(err) }).await
    }

    /// Receive the next complete gRPC message, or `None` at end of stream.
    pub async fn recv_message(&self) -> Result<Option<Vec<u8>>, TransportError> {
        let recv = self.recv.clone();
        on_rt(async move { recv.lock().await.recv_message().await.map_err(err) }).await
    }

    /// Read trailing metadata (e.g. `grpc-status`) after the stream ends.
    pub async fn recv_trailers(&self) -> Result<Vec<GrpcHeader>, TransportError> {
        let recv = self.recv.clone();
        let trailers =
            on_rt(async move { recv.lock().await.recv_trailers().await.map_err(err) }).await?;
        Ok(trailers
            .into_iter()
            .map(|(key, value)| GrpcHeader { key, value })
            .collect())
    }
}
