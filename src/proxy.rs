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

/// Concrete h3 server stream over a quinn bidi stream.
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

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
    let endpoint = Endpoint::server(server_config, bind)?;
    let addr = endpoint.local_addr()?;
    let accept_ep = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = accept_ep.accept().await {
            let upstream = upstream.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(incoming, upstream).await {
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

async fn handle_conn(incoming: quinn::Incoming, upstream: String) -> Result<()> {
    let conn = incoming.await?;
    debug!(rtt = ?conn.rtt(), "QUIC connection accepted");
    let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

    // Each H3 request is an independent gRPC call → proxy concurrently.
    while let Some(resolver) = h3.accept().await? {
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let (req, stream) = match resolver.resolve_request().await {
                Ok(v) => v,
                Err(e) => {
                    warn!("resolve_request: {e}");
                    return;
                }
            };
            if let Err(e) = proxy_request(req, stream, &upstream).await {
                warn!("proxy request failed: {e:#}");
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
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
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
