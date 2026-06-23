//! Client-side QUIC/HTTP-3 gRPC transport — the reusable core the (future)
//! UniFFI surface and the Swift `ClientTransport` adapter will sit on top of.
//!
//! `QuicClient::connect` opens one QUIC/H3 connection; `open_stream` starts a
//! gRPC call. The h3 `SendRequest` is cheaply `Clone`, so calls are multiplexed
//! over the one connection. `QuicStream` carries length-prefixed gRPC messages
//! both ways; h3 0.0.8 also supports client-side `split()` for true full-duplex
//! (used later by the FFI pump — not needed for the sequential API here).

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::{Buf, BytesMut};
use http::Request;
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;

use crate::grpc;
use crate::obf_socket;
use crate::salamander::Salamander;
use crate::tls::{self, CertBundle};

/// QUIC connect handshake timeout. Kept short so a network that silently drops the
/// obfuscated UDP handshake (DPI block) fails over to H2/VEIL fast instead of stalling the
/// user. A working handshake is ~1 RTT; 3s leaves margin for high-latency-but-working links.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;
type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;
type H3SendHalf = h3::client::RequestStream<h3_quinn::SendStream<bytes::Bytes>, bytes::Bytes>;
type H3RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, bytes::Bytes>;

/// One QUIC/HTTP-3 connection to a gateway. Cheap to open streams from.
pub struct QuicClient {
    _endpoint: Endpoint,
    send_request: H3SendRequest,
    authority: String,
    conn: quinn::Connection,
    _driver: tokio::task::JoinHandle<()>,
}

impl QuicClient {
    /// Connect to `host:port`, validating the gateway cert against the pinned
    /// `trust_cert` (a single self-signed DER). `server_name` is the SNI and
    /// must match the cert SAN. (System-root trust for a real cert is a later
    /// phase.)
    pub async fn connect(
        host: &str,
        port: u16,
        server_name: &str,
        trust_cert: Vec<u8>,
    ) -> Result<Self> {
        let client_config = tls::client_config(&Self::trust_bundle(trust_cert))?;

        // Prefer dual-stack IPv6 (NAT64 / IPv6-only LANs), fall back to IPv4.
        let mut endpoint = Endpoint::client("[::]:0".parse().unwrap())
            .or_else(|_| Endpoint::client("0.0.0.0:0".parse().unwrap()))
            .context("bind client endpoint")?;
        endpoint.set_default_client_config(client_config);

        Self::handshake(endpoint, host, port, server_name).await
    }

    /// Like [`connect`](Self::connect) but every datagram is Salamander-obfuscated with `psk`
    /// (the gateway must apply the same PSK). Used as the DPI-evading transport path; the
    /// QUIC MTU is lowered to make room for the per-packet salt. The PSK is provisioned
    /// out-of-band (veil-ticket), never hardcoded.
    pub async fn connect_obfuscated(
        host: &str,
        port: u16,
        server_name: &str,
        trust_cert: Vec<u8>,
        psk: Vec<u8>,
    ) -> Result<Self> {
        let client_config = tls::client_config_obf(&Self::trust_bundle(trust_cert))?;

        // Dual-stack as above, but over a Salamander-obfuscated UDP socket.
        let obf = Salamander::new(psk);
        let mut endpoint =
            obf_socket::obfuscated_client_endpoint("[::]:0".parse().unwrap(), obf.clone())
                .or_else(|_| {
                    obf_socket::obfuscated_client_endpoint("0.0.0.0:0".parse().unwrap(), obf)
                })
                .context("bind obfuscated client endpoint")?;
        endpoint.set_default_client_config(client_config);

        Self::handshake(endpoint, host, port, server_name).await
    }

    fn trust_bundle(trust_cert: Vec<u8>) -> CertBundle {
        CertBundle {
            cert: CertificateDer::from(trust_cert),
            key_der: Vec::new(), // client side: private key unused
        }
    }

    /// Resolve `host:port`, run the QUIC handshake on `endpoint`, and start the h3 driver.
    /// Shared by the plain and obfuscated connect paths — only the endpoint differs.
    async fn handshake(
        endpoint: Endpoint,
        host: &str,
        port: u16,
        server_name: &str,
    ) -> Result<Self> {
        let addr: SocketAddr = (host, port)
            .to_socket_addrs()
            .with_context(|| format!("resolve {host}:{port}"))?
            .next()
            .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;

        let connecting = endpoint
            .connect(addr, server_name)
            .context("start connect")?;
        let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .context("QUIC handshake timed out")?
            .context("QUIC handshake failed")?;

        let conn_for_stats = conn.clone();
        let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Ok(Self {
            _endpoint: endpoint,
            send_request,
            authority: server_name.to_string(),
            conn: conn_for_stats,
            _driver: driver_task,
        })
    }

    /// Diagnostic snapshot of the live quinn connection. `ping` is the count of
    /// keep-alive PING frames sent — if it does not grow over time, keep-alive is not
    /// firing. `close` is the connection's close reason (None while healthy).
    pub fn stats_string(&self) -> String {
        let s = self.conn.stats();
        format!(
            "tx_pkts={} rx_pkts={} ping_tx={} rtt={}ms lost={} close={:?}",
            s.udp_tx.datagrams,
            s.udp_rx.datagrams,
            s.frame_tx.ping,
            self.conn.rtt().as_millis(),
            s.path.lost_packets,
            self.conn.close_reason(),
        )
    }

    /// Open a gRPC call on `path` (`/package.Service/Method`) with extra request
    /// `metadata` headers (e.g. `authorization`). Streams are multiplexed.
    pub async fn open_stream(
        &self,
        path: &str,
        metadata: &[(String, String)],
    ) -> Result<QuicStream> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("https://{}{}", self.authority, path))
            .header("content-type", "application/grpc+proto")
            .header("te", "trailers");
        for (key, value) in metadata {
            builder = builder.header(key.as_str(), value.as_str());
        }
        let req = builder.body(()).context("build request")?;

        let mut send_request = self.send_request.clone();
        let inner = send_request
            .send_request(req)
            .await
            .context("open h3 request")?;
        Ok(QuicStream {
            inner,
            recv_buf: BytesMut::new(),
        })
    }
}

/// One gRPC call over HTTP/3. Messages are length-prefix framed on the wire.
pub struct QuicStream {
    inner: H3RequestStream,
    recv_buf: BytesMut,
}

impl QuicStream {
    /// Await the response headers; returns the HTTP status code.
    pub async fn recv_response(&mut self) -> Result<u16> {
        let resp = self.inner.recv_response().await.context("recv_response")?;
        Ok(resp.status().as_u16())
    }

    /// Send one gRPC message (length-prefix framing is applied here).
    pub async fn send_message(&mut self, message: &[u8]) -> Result<()> {
        self.inner
            .send_data(grpc::encode_frame(message))
            .await
            .context("send_data")
    }

    /// Receive the next complete gRPC message, or `None` at end of stream.
    pub async fn recv_message(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(frame) = grpc::take_frame(&mut self.recv_buf) {
                return Ok(Some(frame.to_vec()));
            }
            match self.inner.recv_data().await.context("recv_data")? {
                Some(mut chunk) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    self.recv_buf.extend_from_slice(&bytes);
                }
                None => return Ok(None),
            }
        }
    }

    /// Half-close the client send side (after the last outbound message).
    pub async fn finish(&mut self) -> Result<()> {
        self.inner.finish().await.context("finish")
    }

    /// Read trailing metadata (e.g. `grpc-status`) after the stream ends.
    pub async fn recv_trailers(&mut self) -> Result<Vec<(String, String)>> {
        let trailers = self.inner.recv_trailers().await.context("recv_trailers")?;
        Ok(trailers
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|v| (k.as_str().to_string(), v.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Split into independent send/recv halves for full-duplex use from two
    /// tasks (h3 0.0.8 supports client-side split). This is the shape the FFI
    /// exposes so Swift can send and receive concurrently on one call.
    pub fn split(self) -> (QuicSendStream, QuicRecvStream) {
        let (send, recv) = self.inner.split();
        (
            QuicSendStream { inner: send },
            QuicRecvStream {
                inner: recv,
                recv_buf: self.recv_buf,
            },
        )
    }
}

/// Send half of a split [`QuicStream`].
pub struct QuicSendStream {
    inner: H3SendHalf,
}

impl QuicSendStream {
    /// Send one gRPC message (length-prefix framing applied here).
    pub async fn send_message(&mut self, message: &[u8]) -> Result<()> {
        self.inner
            .send_data(grpc::encode_frame(message))
            .await
            .context("send_data")
    }

    /// Half-close the client send side.
    pub async fn finish(&mut self) -> Result<()> {
        self.inner.finish().await.context("finish")
    }
}

/// Receive half of a split [`QuicStream`].
pub struct QuicRecvStream {
    inner: H3RecvHalf,
    recv_buf: BytesMut,
}

impl QuicRecvStream {
    /// Await the response headers; returns the HTTP status code.
    pub async fn recv_response(&mut self) -> Result<u16> {
        let resp = self.inner.recv_response().await.context("recv_response")?;
        Ok(resp.status().as_u16())
    }

    /// Receive the next complete gRPC message, or `None` at end of stream.
    pub async fn recv_message(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(frame) = grpc::take_frame(&mut self.recv_buf) {
                return Ok(Some(frame.to_vec()));
            }
            match self.inner.recv_data().await.context("recv_data")? {
                Some(mut chunk) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    self.recv_buf.extend_from_slice(&bytes);
                }
                None => return Ok(None),
            }
        }
    }

    /// Read trailing metadata (e.g. `grpc-status`) after the stream ends.
    pub async fn recv_trailers(&mut self) -> Result<Vec<(String, String)>> {
        let trailers = self.inner.recv_trailers().await.context("recv_trailers")?;
        Ok(trailers
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|v| (k.as_str().to_string(), v.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}
