//! Phase 0.5 gate: a bidi gRPC call over HTTP/3 is reverse-proxied through the
//! native quinn+h3 gateway to an upstream h2c endpoint and back — the shape of
//! `client → quic.konstruct.cc (h3) → envoy:8080 (h2c) → messaging-service`.
//!
//! The upstream here is a minimal hyper h2c server that echoes the request body
//! as the response body (full duplex), standing in for envoy + the echo path.

use std::convert::Infallible;
use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, Bytes, BytesMut};
use construct_transport::{grpc, proxy, tls};
use http::{Request, Response};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::Endpoint;
use tokio::net::TcpListener;

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
async fn bidi_proxied_h3_to_h2c() -> Result<()> {
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

    // ── proxy in front of the upstream ──────────────────────────────────────
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let server_config = tls::server_config(&bundle)?;
    let client_config = tls::client_config(&bundle)?;
    let gw = proxy::serve(server_config, "127.0.0.1:0".parse()?, up_addr.to_string()).await?;

    // ── h3 client ───────────────────────────────────────────────────────────
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(gw.addr, "localhost")?,
    )
    .await
    .expect("handshake timed out")?;
    let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/construct.Echo/BiDi")
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .body(())?;
    let mut stream = send_req.send_request(req).await?;

    let resp = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
        .await
        .expect("recv_response timed out")?;
    assert_eq!(resp.status(), 200, "proxied response should be 200");

    // ── bidi ping-pong through the proxy ────────────────────────────────────
    let mut buf = BytesMut::new();
    for i in 0..3u32 {
        let payload = format!("msg-{i}").into_bytes();
        stream.send_data(grpc::encode_frame(&payload)).await?;
        let echoed = loop {
            if let Some(frame) = grpc::take_frame(&mut buf) {
                break frame;
            }
            match tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
                .await
                .expect("recv_data timed out")?
            {
                Some(mut chunk) => buf.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining())),
                None => panic!("upstream closed before echo {i}"),
            }
        };
        assert_eq!(&echoed[..], &payload[..], "echo mismatch on frame {i}");
    }

    stream.finish().await?;
    drive.abort();
    gw.task.abort();
    Ok(())
}
