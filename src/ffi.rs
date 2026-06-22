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

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::client::{QuicClient, QuicRecvStream, QuicSendStream};

/// Error surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TransportError {
    #[error("{0}")]
    Transport(String),
}

fn err(e: anyhow::Error) -> TransportError {
    TransportError::Transport(format!("{e:#}"))
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
    inner: QuicClient,
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
        let inner = QuicClient::connect(&host, port, &server_name, trust_cert)
            .await
            .map_err(err)?;
        Ok(Arc::new(Self { inner }))
    }

    /// Open a gRPC call on `path` (`/package.Service/Method`) with extra request
    /// `metadata` headers.
    pub async fn open_stream(
        &self,
        path: String,
        metadata: Vec<GrpcHeader>,
    ) -> Result<Arc<QuicStream>, TransportError> {
        let md: Vec<(String, String)> = metadata.into_iter().map(|m| (m.key, m.value)).collect();
        let stream = self.inner.open_stream(&path, &md).await.map_err(err)?;
        let (send, recv) = stream.split();
        Ok(Arc::new(QuicStream {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
        }))
    }
}

/// One gRPC call. Send and receive halves are independently locked, so a Swift
/// sender task and receiver task run concurrently.
#[derive(uniffi::Object)]
pub struct QuicStream {
    send: Mutex<QuicSendStream>,
    recv: Mutex<QuicRecvStream>,
}

#[uniffi::export(async_runtime = "tokio")]
impl QuicStream {
    /// Send one gRPC message.
    pub async fn send_message(&self, message: Vec<u8>) -> Result<(), TransportError> {
        self.send
            .lock()
            .await
            .send_message(&message)
            .await
            .map_err(err)
    }

    /// Half-close the client send side.
    pub async fn finish(&self) -> Result<(), TransportError> {
        self.send.lock().await.finish().await.map_err(err)
    }

    /// Await the response headers; returns the HTTP status code.
    pub async fn recv_response(&self) -> Result<u16, TransportError> {
        self.recv.lock().await.recv_response().await.map_err(err)
    }

    /// Receive the next complete gRPC message, or `None` at end of stream.
    pub async fn recv_message(&self) -> Result<Option<Vec<u8>>, TransportError> {
        self.recv.lock().await.recv_message().await.map_err(err)
    }

    /// Read trailing metadata (e.g. `grpc-status`) after the stream ends.
    pub async fn recv_trailers(&self) -> Result<Vec<GrpcHeader>, TransportError> {
        let trailers = self.recv.lock().await.recv_trailers().await.map_err(err)?;
        Ok(trailers
            .into_iter()
            .map(|(key, value)| GrpcHeader { key, value })
            .collect())
    }
}
