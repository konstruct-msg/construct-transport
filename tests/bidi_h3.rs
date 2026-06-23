//! Phase 0 gate: bidi gRPC-over-HTTP/3 round-trips against a native quinn+h3
//! server (no Traefik). Proves the exact path that silent-failed in 2026-05:
//! the server's initial response HEADERS reaching the client on a bidi stream.

use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, BytesMut};
use construct_transport::{echo_server, grpc, tls};
use http::Request;
use quinn::Endpoint;

#[tokio::test]
async fn bidi_grpc_over_h3_roundtrips() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ── server ───────────────────────────────────────────────────────────
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let server_config = tls::server_config(&bundle)?;
    let client_config = tls::client_config(&bundle)?;
    let server = echo_server::spawn_echo_server(server_config, "127.0.0.1:0".parse()?).await?;
    let addr = server.addr;

    // ── client QUIC endpoint ─────────────────────────────────────────────
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let conn = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(addr, "localhost")?)
        .await
        .expect("QUIC handshake timed out")?;

    let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // ── open a bidi MessageStream-style POST ─────────────────────────────
    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/construct.Echo/BiDi")
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .body(())?;
    let mut stream = send_req.send_request(req).await?;

    // ★ THE GATE: response HEADERS must arrive on a bidi stream BEFORE the
    //   client sends or finishes any data. This is precisely what
    //   silent-failed through the Traefik QUIC↔h2c bridge.
    let resp = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
        .await
        .expect("recv_response timed out — the prior bidi failure mode")?;
    assert_eq!(resp.status(), 200, "expected gRPC 200 response headers");

    // ── bidi ping-pong while the stream stays open both ways ──────────────
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
                None => panic!("server closed before echo {i}"),
            }
        };
        assert_eq!(&echoed[..], &payload[..], "echo mismatch on frame {i}");
    }

    // ── half-close, drain, read trailers ─────────────────────────────────
    stream.finish().await?;
    while (stream.recv_data().await?).is_some() {}
    if let Some(trailers) = stream.recv_trailers().await?
        && let Some(status) = trailers.get("grpc-status")
    {
        assert_eq!(status, "0", "grpc-status should be OK");
    }

    drive.abort();
    server.task.abort();
    Ok(())
}
