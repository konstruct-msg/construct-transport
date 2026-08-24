//! Client-side QUIC/HTTP-3 gRPC transport — the reusable core the (future)
//! UniFFI surface and the Swift `ClientTransport` adapter will sit on top of.
//!
//! `QuicClient::connect` opens one QUIC/H3 connection; `open_stream` starts a
//! gRPC call. The h3 `SendRequest` is cheaply `Clone`, so calls are multiplexed
//! over the one connection. `QuicStream` carries length-prefixed gRPC messages
//! both ways; h3 0.0.8 also supports client-side `split()` for true full-duplex
//! (used later by the FFI pump — not needed for the sequential API here).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::{Buf, BytesMut};
use http::Request;
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;

use crate::grpc;
use crate::obf_socket;
use crate::salamander::Salamander;
use crate::spin_free_socket::SpinFreeUdpSocket;
use crate::tls::{self, CertBundle};

/// Everything `connect` may spend before the caller has already stopped waiting.
///
/// This is not our number. iOS abandons fast-UDP at `NetworkTiming.GRPC.streamOpenAcceptTimeoutH3`
/// (1.5s) and marks QUIC failed for the whole session; nothing here can change that verdict, it
/// can only arrive after it. Which is what used to happen — the handshake budget was 3s, so on the
/// 2026-08-24 device run the session was downgraded to H2 at 09:41:28 and this crate's
/// "handshake timed out" was logged at 09:41:29, a second *after* the decision it was supposed to
/// explain, having kept a doomed endpoint polling for that second.
///
/// Two deadlines for one question, and the one that decided was in the other repo. Lowering this
/// costs no connection that could have been kept: every observed failure burned the full 3s, and
/// a handshake slower than 1.5s was never going to be used.
const CONNECT_BUDGET: Duration = Duration::from_millis(1500);

/// Name resolution budget — inside `CONNECT_BUDGET`, and reported under its own name.
///
/// It exists to make the failure *attributable*: "DNS timed out" and "handshake timed out" are
/// different problems and used to arrive under the same name. That only works if it can actually
/// fire before the caller gives up, which is why it is a third of the budget and not, as it was
/// until now, longer than the whole of it.
const RESOLVE_TIMEOUT: Duration = Duration::from_millis(500);

/// QUIC handshake budget: what is left of `CONNECT_BUDGET` after resolution — derived, not
/// written down again, so the two phases cannot sum past the budget by editing one of them.
///
/// A working handshake is ~1 RTT — 85ms to the Amsterdam gateway on the run that proved the
/// address-family fix — so a second is twelve of them. Short is the point: a network that silently
/// drops the UDP handshake must fail over to H2/VEIL, not stall the user.
const HANDSHAKE_TIMEOUT: Duration = CONNECT_BUDGET.saturating_sub(RESOLVE_TIMEOUT);

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;
type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;
type H3SendHalf = h3::client::RequestStream<h3_quinn::SendStream<bytes::Bytes>, bytes::Bytes>;
type H3RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, bytes::Bytes>;

/// Live `QuicClient` count. A gauge, not a statistic: an abandoned connection used to be
/// invisible, and on device it was the difference between 13% and 106% CPU.
static LIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// How many QUIC connections this process currently holds **open**.
///
/// Open, not referenced. Until 2026-08-23 only `Drop` decremented this, so a connection retired
/// through `close()` — which is the path the iOS transport takes on reconnect — kept counting
/// while a parked stream held the last `Arc`. The device reads that gauge in its RUNTIME line, so
/// the signature of a *healthy* session was `conns=1` beside a flat UDP error count, which is the exact
/// signature of the leak it exists to detect. A gauge that cannot distinguish the fixed state
/// from the broken one is worse than no gauge on the run that has to tell them apart.
pub fn live_connections() -> u32 {
    LIVE_CONNECTIONS.load(Ordering::Relaxed) as u32
}

/// One QUIC/HTTP-3 connection to a gateway. Cheap to open streams from.
///
/// Dropping this closes the connection — see the `Drop` impl. That is not the default
/// behaviour of the parts it is built from, and the difference cost a day of device logs.
pub struct QuicClient {
    endpoint: Endpoint,
    send_request: H3SendRequest,
    authority: String,
    conn: quinn::Connection,
    driver: tokio::task::JoinHandle<()>,
    /// Set by the first retirement, whether that is `close()` or `Drop`. The two are the same
    /// teardown reached from different directions, and the gauge must fall exactly once.
    retired: AtomicBool,
}

impl Drop for QuicClient {
    /// Full teardown: connection, h3 driver, endpoint, gauge.
    ///
    /// History matters here, because two of these four were added on a theory that turned out to
    /// be wrong, and the third is the one that actually fixed the heat.
    ///
    /// 2026-08-09, first attempt: written believing abandoned *connections* accumulated. Mutation
    /// refuted it — emptying this whole body left `tests/connection_teardown.rs` green, held
    /// stream and all. Dropping the client already closed the connection.
    ///
    /// 2026-08-10, the Time Profiler answered it: `Endpoint::close`. The endpoint driver, not the
    /// connection, was spinning in `recvmsg`. See `close_endpoint` for the stack and the mechanism.
    ///
    /// So each line earns its place differently, and none is decoration:
    ///   * `conn.close()` — states intent at the peer instead of relying on handle-drop order
    ///     inside two dependencies. Not load-bearing; kept deliberately.
    ///   * `driver.abort()` — a detached task is a real leak even when the connection closes.
    ///   * `close_endpoint()` — **the fix.** Nothing else stops the endpoint driver.
    ///   * the gauge — what made the device diagnosable at all (`conns=0 tasks=1` is what ruled
    ///     out both accumulation theories and pointed at a single spinning task).
    fn drop(&mut self) {
        self.retire(b"client dropped");
    }
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

        let addr = Self::resolve(host, port).await?;
        let mut endpoint =
            Self::bind_endpoint(Self::bind_addr_for(addr)).context("bind client endpoint")?;
        endpoint.set_default_client_config(client_config);

        Self::handshake(endpoint, addr, server_name).await
    }

    /// The local address to bind so this destination is reachable from the socket.
    ///
    /// **The bug this replaces.** The endpoint used to bind `[::]:0` and fall back to `0.0.0.0:0`
    /// only if that failed — "prefer dual-stack IPv6 (NAT64 / IPv6-only LANs)". Binding `[::]`
    /// succeeds almost everywhere, so almost everywhere the socket was `AF_INET6`. Sending to a
    /// plain `AF_INET` destination from an `AF_INET6` socket does not work: the address has to be
    /// v4-mapped (`::ffff:a.b.c.d`), and quinn passes `Transmit.destination` through unchanged.
    /// `quic.konstruct.cc` has an A record and no AAAA, so every datagram failed to leave, the
    /// handshake expired at its 3s timeout, and it read as "UDP is blocked on this path".
    ///
    /// Nothing contradicted that reading, because the only counter there was — printed as
    /// `udperr` — counted **receive** errors (`spin_free_socket::poll_recv`), so sends that never
    /// left were invisible to it. Closed 2026-08-24: the field is now `udprecv_err` beside
    /// `udpsend_err`, and this failure would announce itself. And it did
    /// work occasionally: on a NAT64 carrier network DNS64 synthesises an AAAA, resolution returns
    /// an IPv6 address, and the IPv6 socket sends it happily. One success in five, which read as a
    /// flaky network rather than as the address family it actually was.
    ///
    /// Verified 2026-08-24: `cargo run --bin probe` binds `0.0.0.0:0` and completes the same
    /// handshake to the same gateway in 56ms, from the same building.
    ///
    /// Matching the family to the resolved address is picked over v4-mapping the destination
    /// because it stays correct in both directions — a v4-mapped destination is wrong the moment
    /// the socket is IPv4, which is exactly what the old fallback produced.
    fn bind_addr_for(peer: SocketAddr) -> SocketAddr {
        match peer {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("literal"),
            SocketAddr::V6(_) => "[::]:0".parse().expect("literal"),
        }
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

        // Same family rule as the plain path — see `bind_addr_for`.
        let obf = Salamander::new(psk);
        let addr = Self::resolve(host, port).await?;
        let mut endpoint = obf_socket::obfuscated_client_endpoint(Self::bind_addr_for(addr), obf)
            .context("bind obfuscated client endpoint")?;
        endpoint.set_default_client_config(client_config);

        Self::handshake(endpoint, addr, server_name).await
    }

    /// Bind a client endpoint on our own socket rather than `Endpoint::client`.
    ///
    /// `Endpoint::client` wraps quinn's tokio socket, whose `poll_recv` re-polls immediately on
    /// any receive error that is not `WouldBlock` — which pins a CPU core while the connection
    /// itself keeps working. This is the plain path, and it is the one the device burned on:
    /// `transport=conns=1 tasks=5`, 111% CPU, thermal `serious`, 1.43 min of `__recvmsg` in a
    /// 1.59 min trace. See `spin_free_socket`.
    fn bind_endpoint(addr: std::net::SocketAddr) -> Result<Endpoint> {
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC endpoint"))?;
        let socket = Arc::new(SpinFreeUdpSocket::bind(addr)?);
        Ok(Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )?)
    }

    fn trust_bundle(trust_cert: Vec<u8>) -> CertBundle {
        CertBundle {
            cert: CertificateDer::from(trust_cert),
            key_der: Vec::new(), // client side: private key unused
        }
    }

    /// Name resolution: async, bounded, and reported under its own name.
    ///
    /// It used to be a blocking `to_socket_addrs()` inside `handshake` and *outside*
    /// `HANDSHAKE_TIMEOUT` — a getaddrinfo blocking a tokio worker with no deadline of its own,
    /// whose failures surfaced as "QUIC handshake timed out" because that was the only error the
    /// caller could reach.
    ///
    /// It now also runs **before** the socket is bound, because the resolved address decides the
    /// socket family. See `bind_addr_for`.
    async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
        tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .with_context(|| format!("DNS timed out for {host}:{port}"))?
            .with_context(|| format!("resolve {host}:{port}"))?
            .next()
            .ok_or_else(|| anyhow!("no address for {host}:{port}"))
    }

    /// Run the QUIC handshake on an already-bound `endpoint` and start the h3 driver.
    /// Shared by the plain and obfuscated connect paths — only the endpoint differs.
    async fn handshake(endpoint: Endpoint, addr: SocketAddr, server_name: &str) -> Result<Self> {
        // Every early return from here on must close the endpoint. A failed attempt leaves no
        // connection behind, so nothing else will ever stop its driver — and a handshake failing
        // is exactly the situation (blocked UDP) that makes that driver spin. See `close_endpoint`.
        let attempt = async {
            let connecting = endpoint
                .connect(addr, server_name)
                .context("start connect")?;
            tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
                .await
                .context("QUIC handshake timed out")?
                .context("QUIC handshake failed")
        };
        let conn = match attempt.await {
            Ok(conn) => conn,
            Err(e) => {
                Self::close_endpoint(&endpoint);
                return Err(e);
            }
        };

        let conn_for_stats = conn.clone();
        let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        LIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            endpoint,
            send_request,
            authority: server_name.to_string(),
            conn: conn_for_stats,
            driver: driver_task,
            retired: AtomicBool::new(false),
        })
    }

    /// A clone of the endpoint handle, for asserting after this client is gone that its driver
    /// was actually stopped. Test/diagnostic use — `Endpoint` is a handle, not the driver.
    pub fn endpoint_handle(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// A clone of the quinn connection handle, for observing state (`close_reason`) after this
    /// client is gone. Test/diagnostic use — it does not keep the connection open on its own.
    pub fn connection_handle(&self) -> quinn::Connection {
        self.conn.clone()
    }

    /// Close the connection now, without waiting for every reference to go away.
    ///
    /// `Drop` does this too, but an open `QuicStream` holds the connection alive, so a caller
    /// that abandons a channel while a stream is still parked on `recv_message` would otherwise
    /// keep the whole thing running. Idempotent — quinn ignores a second close.
    pub fn close(&self) {
        self.retire(b"client closed");
    }

    /// The one teardown, reached from `close()` and from `Drop`.
    ///
    /// Each line is explained in the `Drop` doc comment above — only the gauge is new here, and
    /// only its placement: it must fall on the first retirement, not on the last reference, and
    /// it must fall once. `swap` is what makes "once" true without a lock; a second retirement is
    /// otherwise entirely legal and happens on every explicit close (the `Arc` still drops later).
    fn retire(&self, reason: &[u8]) {
        self.conn.close(0u32.into(), reason);
        self.driver.abort();
        // Shut the endpoint down, not just the connection. This is the 2026-08-10 heat fix —
        // see `close_endpoint` for why dropping the handle is not enough.
        Self::close_endpoint(&self.endpoint);
        if !self.retired.swap(true, Ordering::Relaxed) {
            LIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Stop quinn's endpoint driver.
    ///
    /// THE HEAT FIX (device, Time Profiler, 2026-08-10). One tokio worker at 90% of a 1.5-minute
    /// trace, all of it here:
    ///
    /// ```text
    ///   quinn::endpoint::EndpointDriver::poll            86.5%
    ///     RecvState::poll_socket                         86.4%
    ///       UdpSocket::poll_recv                         86.2%
    ///         tokio Registration::try_io                 84.1%
    ///           quinn_udp::UdpSocketState::recv          83.0%   ← 1.37 min of SELF time
    ///             std::io::error::Error::kind             0.5%
    ///             recvmsg                                 0.1%
    /// ```
    ///
    /// `recvmsg` returns an error, the error kind is inspected, and the loop runs again
    /// immediately — for as long as the app is foregrounded. On Darwin a UDP socket surfaces ICMP
    /// unreachables as a pending socket error, and `Registration::try_io` only clears readiness
    /// when the closure reports `WouldBlock`; any other error leaves the socket marked ready, so
    /// the driver is re-polled at once. A blocked UDP path therefore pins a core.
    ///
    /// This is also why it never reproduced locally: `tests/runtime_drains.rs` blackholes the
    /// handshake through TEST-NET-3, which drops packets *silently*. No ICMP, no socket error, no
    /// spin. The harness could only ever have staged the healthy case.
    ///
    /// Dropping the `Endpoint` handle does not stop the driver — quinn keeps it alive while any
    /// connection exists, and on the failed-handshake path there is no connection to close at
    /// all. `Endpoint::close` is the thing that ends it.
    fn close_endpoint(endpoint: &Endpoint) {
        endpoint.close(0u32.into(), b"endpoint retired");
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

#[cfg(test)]
mod bind_family_tests {
    use super::*;

    /// The socket family must follow the destination.
    ///
    /// Binding `[::]` and sending to a plain `AF_INET` peer does not work — the address has to be
    /// v4-mapped, and quinn forwards `Transmit.destination` unchanged. The old code preferred
    /// `[::]:0` and fell back to IPv4 only if the *bind* failed, which it essentially never does,
    /// so on any network resolving `quic.konstruct.cc` (A record, no AAAA) to IPv4 nothing left
    /// the socket. It read as blocked UDP for three device runs, because the RUNTIME line's only
    /// UDP counter answered about receiving, so sends that never happened left no trace. The send
    /// counter added on 2026-08-24 (`udpsend_err`) is what makes this shape self-reporting.
    ///
    /// Mutation: always return `[::]:0` — restores the bug.
    #[test]
    fn an_ipv4_peer_gets_an_ipv4_socket() {
        let peer: SocketAddr = "152.42.130.140:443".parse().unwrap();
        let bind = QuicClient::bind_addr_for(peer);
        assert!(
            bind.is_ipv4(),
            "IPv4 peer must be reached from an IPv4 socket, got {bind}"
        );
        assert_eq!(bind.port(), 0, "the port must stay ephemeral");
    }

    /// The NAT64 case, and the reason the old code preferred IPv6 in the first place: on a
    /// carrier network DNS64 synthesises an AAAA and resolution returns IPv6. That path worked
    /// before and must keep working — it is why the failure looked intermittent.
    ///
    /// Mutation: always return `0.0.0.0:0` — breaks IPv6-only networks instead.
    #[test]
    fn an_ipv6_peer_gets_an_ipv6_socket() {
        let peer: SocketAddr = "[64:ff9b::9852:828c]:443".parse().unwrap();
        let bind = QuicClient::bind_addr_for(peer);
        assert!(
            bind.is_ipv6(),
            "IPv6 peer must be reached from an IPv6 socket, got {bind}"
        );
        assert_eq!(bind.port(), 0);
    }

    /// Neither family may be hardcoded: the two answers must differ.
    #[test]
    fn the_two_families_do_not_collapse() {
        let v4 = QuicClient::bind_addr_for("1.2.3.4:443".parse().unwrap());
        let v6 = QuicClient::bind_addr_for("[2001:db8::1]:443".parse().unwrap());
        assert_ne!(v4, v6);
    }

    /// Resolution must not eat the budget it shares.
    ///
    /// `HANDSHAKE_TIMEOUT` is now derived, so the sum can no longer exceed `CONNECT_BUDGET` —
    /// but raising `RESOLVE_TIMEOUT` silently shrinks the handshake instead, and at 1.5s it
    /// saturates the handshake to zero and every connect fails instantly. That is the failure
    /// this guards: the old values (resolve 2s, handshake 3s, caller 1.5s) were each defensible
    /// on their own and only wrong together.
    #[test]
    fn resolution_leaves_the_handshake_a_usable_window() {
        assert!(
            HANDSHAKE_TIMEOUT >= Duration::from_millis(500),
            "resolve {RESOLVE_TIMEOUT:?} leaves only {HANDSHAKE_TIMEOUT:?} of {CONNECT_BUDGET:?} \
             for the handshake — the measured one is ~85ms, so this is under six of them"
        );
        assert!(
            RESOLVE_TIMEOUT < HANDSHAKE_TIMEOUT,
            "resolution is one round trip and the handshake is at least one — a resolve budget \
             at or above the handshake's spends the window on the cheaper phase"
        );
    }
}
