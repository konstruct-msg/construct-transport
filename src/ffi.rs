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
//! ## Why every operation runs on a dedicated, continuously-driven runtime (`RT`)
//!
//! quinn drives a connection's I/O — including the keep-alive timer, outgoing-packet
//! flushing, and incoming-packet processing — from a background driver task owned by the
//! endpoint. That task only makes progress while the runtime's I/O + time reactor is being
//! actively pumped. UniFFI's `async_runtime = "tokio"` only drives the *specific exported
//! future* the foreign side is awaiting; it does NOT keep the reactor running between calls.
//! So on iOS the connection worked for the first exchange (while `connect`/`recv` were
//! actively polled) and then froze: once every FFI call parked, nothing pumped the reactor,
//! so no keep-alive PINGs went out, queued sends never flushed, and incoming packets were
//! never processed — the connection idle-timed out at ~30s (client "open timed out" / gateway
//! "h3 recv_data: Timeout").
//!
//! The 2026-06-23 fix moved all work onto a dedicated **multi-thread** runtime, which fixed
//! the *active-flush* starvation but NOT idle: a multi-thread runtime only pumps its reactor
//! when a worker parks, and on iOS that cooperative park→reactor path does not keep the
//! endpoint driver's keep-alive timer / socket recv alive through a long idle window. Device
//! telemetry (`connection_stats`) proved it: `ping_tx` frozen (keep-alive never fires) and
//! `rx_pkts` frozen (socket never read) while `tx_pkts` grew only on explicit `send_message`.
//!
//! The 2026-07-20 fix (this code) switches to the standard **persistent background runtime**
//! idiom: a `current_thread` runtime driven forever by one dedicated OS thread holding
//! `block_on(pending())`. That thread continuously advances the reactor (kqueue + timer
//! wheel), so quinn's endpoint driver, keep-alive timer, and socket recv always make progress
//! independent of how UniFFI polls the exported futures. Verify on-device: `QUIC stats`
//! `ping_tx` must grow and `rx_pkts` advance over an idle window; the idle MessageStream must
//! survive well past 30s. Low CPU — the thread parks on kqueue between events/timers.

use std::sync::{Arc, LazyLock};

use tokio::sync::Mutex;

use crate::client::{QuicClient, QuicRecvStream, QuicSendStream};

/// Dedicated tokio runtime that owns all QUIC/h3 work, driven **continuously** by one
/// background thread so quinn's endpoint driver (keep-alive, flush, recv) always makes
/// progress — independent of how UniFFI polls the exported futures. A `current_thread`
/// runtime advances spawned tasks and its I/O/time reactor only while something is being
/// `block_on`'d; the dedicated thread holds that `block_on` for the process lifetime. See
/// module docs for why the previous multi-thread runtime did not keep idle keep-alive alive
/// on iOS.
static RT: LazyLock<tokio::runtime::Handle> = LazyLock::new(|| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build construct-transport tokio runtime");
    let handle = rt.handle().clone();
    std::thread::Builder::new()
        .name("construct-transport".into())
        .spawn(move || {
            // Hold the runtime open forever so its reactor + all spawned QUIC tasks are
            // driven for the whole process life. Parks on kqueue between events (low CPU).
            rt.block_on(std::future::pending::<()>());
        })
        .expect("spawn construct-transport runtime thread");
    handle
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
    "quic-idle-drive-current-thread-2026-07-20".to_string()
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
