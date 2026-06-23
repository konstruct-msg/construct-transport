//! Phase 4 chunk 3 gate: the **real** obfuscated client path
//! (`QuicClient::connect_obfuscated`) talks to the **real** obfuscated gateway
//! (`proxy::serve_obfuscated`) and a bidi gRPC call is reverse-proxied to an h2c
//! upstream and back — every datagram Salamander-obfuscated with a shared PSK.
//!
//! This is the first test that exercises the client-side connect path and the
//! gateway listener together (salamander_h3 used raw quinn endpoints). It proves
//! the obfuscation contract is symmetric end-to-end through the proxy.

use std::convert::Infallible;

use anyhow::Result;
use bytes::Bytes;
use construct_transport::client::QuicClient;
use construct_transport::{proxy, tls};
use http::{Request, Response};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

const PSK: &[u8] = b"obf-proxy-host-test-psk";

/// h2c upstream: echo the request body straight back as the response body.
async fn echo_upstream(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
    let body = req.into_body().boxed();
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(body)
        .unwrap())
}

#[tokio::test]
async fn obfuscated_client_proxied_through_obfuscated_gateway() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ── upstream h2c echo server (stands in for envoy → messaging) ───────────
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service_fn(echo_upstream))
                    .await;
            });
        }
    });

    // ── obfuscated gateway in front of the upstream ──────────────────────────
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let gw = proxy::serve_obfuscated(
        &bundle,
        "127.0.0.1:0".parse()?,
        up_addr.to_string(),
        PSK.to_vec(),
    )
    .await?;
    let port = gw.addr.port();

    // ── real obfuscated client (matching PSK + pinned cert) ──────────────────
    let trust_cert = bundle.cert.as_ref().to_vec();
    let client =
        QuicClient::connect_obfuscated("127.0.0.1", port, "localhost", trust_cert, PSK.to_vec())
            .await?;

    let mut stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;
    let status = stream.recv_response().await?;
    assert_eq!(status, 200, "obfuscated proxied response should be 200");

    // ── bidi ping-pong through the obfuscated proxy ──────────────────────────
    for i in 0..3u32 {
        let payload = format!("obf-proxy-{i}").into_bytes();
        stream.send_message(&payload).await?;
        let echoed = stream
            .recv_message()
            .await?
            .expect("upstream closed before echo");
        assert_eq!(echoed, payload, "obfuscated proxied echo mismatch on {i}");
    }

    stream.finish().await?;
    gw.task.abort();
    Ok(())
}
