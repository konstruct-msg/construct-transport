//! h3 → h2c gRPC reverse proxy (Phase 0.5).
//!
//! Terminates QUIC/HTTP-3 from clients on a native quinn+h3 endpoint and
//! forwards each gRPC call to an upstream h2c endpoint (`envoy:8080`) — the
//! same upstream Traefik already uses. This bypasses the Traefik QUIC↔h2c
//! bridge (the Phase 0 culprit) while leaving every tonic handler untouched.
//!
//! Full-duplex: the h3 server `RequestStream` is `split()` into independent
//! send/recv halves driven by two tasks, and the upstream hyper h2 connection
//! is natively duplex — so a long-lived bidi `MessageStream` flows both ways
//! without the polling pump the engine client needs.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::Endpoint;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::h3_guard;
use crate::obf_socket;
use crate::salamander::Salamander;

/// Concrete h3 server stream over a quinn bidi stream.
type H3Stream = h3::server::RequestStream<h3_guard::BidiStream, Bytes>;

/// What the gateway takes on, across all peers. What one connection may hold is in
/// [`tls::server_config`](crate::tls::server_config) and [`h3_guard`].
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Connections open at once; the next one is refused (`CONNECTION_REFUSED`), so the client
    /// learns it in one round trip and takes its H2 path instead of waiting for a timeout.
    ///
    /// Measured 2026-11-23/24 (construct-docs todo 332): never more than two at once. 256 is there
    /// to bound memory, not to shape traffic.
    pub max_connections: usize,
    /// Above this many, a peer must show it receives at its address (Retry, RFC 9000 §8.1.2)
    /// before any state is kept for it, so that forged addresses cannot fill the table. Costs the
    /// newcomer one round trip; below it, nothing changes.
    pub validate_above: usize,
    /// How long an upstream call outlives the client's connection: time for what the client
    /// already sent to go up. The answer has nobody to go to.
    pub orphan_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            validate_above: 128,
            orphan_grace: Duration::from_secs(10),
        }
    }
}

/// Refusals are counted and reported on one line per window: a line each would turn a flood into
/// a full disk.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// Bytes of one call the gateway holds on the upstream side, each way.
const UPSTREAM_WINDOW: u32 = 64 * 1024;

/// A running proxy: bound address, the endpoint, and the accept task.
pub struct ProxyHandle {
    pub addr: SocketAddr,
    pub endpoint: Endpoint,
    pub task: tokio::task::JoinHandle<()>,
}

/// Bind a quinn endpoint and proxy every inbound gRPC-over-H3 call to `upstream`
/// (an `host:port` reachable over plaintext HTTP/2, e.g. `envoy:8080`).
pub async fn serve(
    server_config: quinn::ServerConfig,
    bind: SocketAddr,
    upstream: String,
) -> Result<ProxyHandle> {
    serve_with_limits(server_config, bind, upstream, Limits::default()).await
}

/// [`serve`] with limits other than the default ones (tests).
pub async fn serve_with_limits(
    server_config: quinn::ServerConfig,
    bind: SocketAddr,
    upstream: String,
    limits: Limits,
) -> Result<ProxyHandle> {
    serve_on_endpoint(Endpoint::server(server_config, bind)?, upstream, limits)
}

/// Like [`serve`] but Salamander-obfuscates every datagram with `psk` (the DPI-evading
/// listener). Clients MUST connect with the same PSK via `QuicChannel::connect_obfuscated`;
/// a plain QUIC client cannot complete the handshake. `psk` is provisioned out-of-band
/// (veil-ticket), never hardcoded. The QUIC MTU is lowered to make room for the salt.
pub async fn serve_obfuscated(
    bundle: &crate::tls::CertBundle,
    bind: SocketAddr,
    upstream: String,
    psk: Vec<u8>,
) -> Result<ProxyHandle> {
    let server_config = crate::tls::server_config_obf(bundle)?;
    let endpoint =
        obf_socket::obfuscated_server_endpoint(bind, Salamander::new(psk), server_config)?;
    serve_on_endpoint(endpoint, upstream, Limits::default())
}

/// Run the accept-loop on a pre-built endpoint — shared by the plain and obfuscated paths
/// (only the underlying UDP socket / MTU differs).
fn serve_on_endpoint(endpoint: Endpoint, upstream: String, limits: Limits) -> Result<ProxyHandle> {
    let addr = endpoint.local_addr()?;
    let accept_ep = endpoint.clone();
    let task = tokio::spawn(async move {
        let mut refused = 0u64;
        let mut report = tokio::time::interval(REPORT_EVERY);
        loop {
            let incoming = tokio::select! {
                incoming = accept_ep.accept() => match incoming {
                    Some(incoming) => incoming,
                    None => break,
                },
                _ = report.tick() => {
                    if refused > 0 {
                        warn!(
                            refused,
                            open = accept_ep.open_connections(),
                            max = limits.max_connections,
                            "gateway full: connections refused in the last minute"
                        );
                        refused = 0;
                    }
                    continue;
                }
            };
            // Capacity first, then address validation: the order of quinn's own server example
            // (`quinn/examples/server.rs`).
            let open = accept_ep.open_connections();
            if open >= limits.max_connections {
                incoming.refuse();
                refused += 1;
                continue;
            }
            if open >= limits.validate_above && !incoming.remote_address_validated() {
                // Cannot fail: an address that is not validated may always be asked to retry.
                let _ = incoming.retry();
                continue;
            }
            // Accepted here and not in the task: this is what makes it count as open before the
            // next one is looked at.
            let connecting = match incoming.accept() {
                Ok(connecting) => connecting,
                Err(e) => {
                    debug!("accept: {e}");
                    continue;
                }
            };
            let upstream = upstream.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(connecting, upstream, limits.orphan_grace).await {
                    warn!("connection ended: {e:#}");
                }
            });
        }
    });
    Ok(ProxyHandle {
        addr,
        endpoint,
        task,
    })
}

async fn handle_conn(
    connecting: quinn::Connecting,
    upstream: String,
    orphan_grace: Duration,
) -> Result<()> {
    let conn = connecting.await?;
    debug!(rtt = ?conn.rtt(), "QUIC connection accepted");
    let mut h3 = h3::server::builder()
        .max_field_section_size(h3_guard::MAX_BUFFERED_FRAME)
        .build(h3_guard::Connection::new(conn.clone()))
        .await?;

    // Each H3 request is an independent gRPC call → proxy concurrently.
    while let Some(resolver) = h3.accept().await? {
        let upstream = upstream.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            let (req, stream) = match resolver.resolve_request().await {
                Ok(v) => v,
                Err(e) => {
                    warn!("resolve_request: {e}");
                    return;
                }
            };
            let orphaned = async {
                conn.closed().await;
                tokio::time::sleep(orphan_grace).await;
            };
            tokio::select! {
                ended = proxy_request(req, stream, &upstream) => {
                    if let Err(e) = ended {
                        warn!("proxy request failed: {e:#}");
                    }
                }
                () = orphaned => debug!("upstream call dropped: the client is gone"),
            }
        });
    }
    Ok(())
}

async fn proxy_request(req: Request<()>, stream: H3Stream, upstream: &str) -> Result<()> {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    debug!(%path, "proxying gRPC call to upstream");

    // ── dial upstream over h2c (prior knowledge, no TLS) ────────────────────
    let tcp = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("dial upstream {upstream}"))?;
    tcp.set_nodelay(true).ok();
    let io = TokioIo::new(tcp);
    // One call per h2 connection, over loopback: windows larger than the protocol's default buy no
    // speed here, they only are what a client that does not read can make the gateway hold
    // (hyper's defaults: 2 MiB per stream, 1 MiB of send buffer).
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(UPSTREAM_WINDOW)
        .max_send_buf_size(UPSTREAM_WINDOW as usize)
        .handshake(io)
        .await
        .context("upstream h2 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("upstream connection closed: {e}");
        }
    });

    // ── build the upstream request: same method/path/headers, streamed body ──
    // Body is fed by the client→upstream pump below.
    let (body_tx, body_rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(64);
    let up_body = StreamBody::new(ReceiverStream::new(body_rx));

    let uri = format!("http://{upstream}{path}");
    let mut up_builder = Request::builder().method(req.method()).uri(uri);
    for (name, value) in req.headers() {
        // skip hop-by-hop / connection-specific headers
        if name == http::header::HOST || name == http::header::CONNECTION {
            continue;
        }
        up_builder = up_builder.header(name, value);
    }
    let up_req = up_builder.body(up_body).context("build upstream request")?;

    // ── split the h3 stream into independent send/recv halves ───────────────
    let (mut h3_send, mut h3_recv) = stream.split();

    // ── pump A: client → upstream ───────────────────────────────────────────
    let c2u = tokio::spawn(async move {
        loop {
            match h3_recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    if body_tx.send(Ok(Frame::data(bytes))).await.is_err() {
                        break; // upstream gone
                    }
                }
                Ok(None) => break, // client half-closed its send side
                Err(e) => {
                    warn!("h3 recv_data: {e}");
                    break;
                }
            }
        }
        // drop body_tx → upstream request body ends
    });

    // ── send request, forward response headers downstream ───────────────────
    let resp = sender
        .send_request(up_req)
        .await
        .context("upstream send_request")?;

    let mut down = Response::builder().status(resp.status());
    for (name, value) in resp.headers() {
        down = down.header(name, value);
    }
    h3_send
        .send_response(down.body(()).context("build downstream response")?)
        .await
        .context("h3 send_response")?;

    // ── pump B: upstream → client (data frames, then trailers) ──────────────
    let mut body = resp.into_body();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("upstream body frame")?;
        match frame.into_data() {
            Ok(data) => h3_send.send_data(data).await.context("h3 send_data")?,
            Err(non_data) => {
                if let Ok(trailers) = non_data.into_trailers() {
                    h3_send
                        .send_trailers(trailers)
                        .await
                        .context("h3 send_trailers")?;
                }
            }
        }
    }
    h3_send.finish().await.context("h3 finish")?;

    c2u.abort();
    Ok(())
}
