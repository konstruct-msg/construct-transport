//! Keep-alive gate: a QUIC/h3 connection that sits idle longer than the idle timeout
//! must survive, because both ends send keep-alive PINGs. Reproduces the device/gateway
//! bug where a long-lived MessageStream died ~30s after connect (no keep-alive → idle
//! timeout) and reconnected forever.
//!
//! Uses short timeouts (keep_alive 300ms, max_idle 1500ms) and an idle gap of ~4s — far
//! beyond the idle ceiling. If keep-alive works the second exchange succeeds; if it is
//! broken the connection is dead by then and recv_data/send_data fail.

use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, BytesMut};
use construct_transport::{echo_server, grpc, tls};
use http::Request;
use quinn::Endpoint;

#[tokio::test]
async fn idle_connection_survives_via_keep_alive() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let keep_alive = Duration::from_millis(300);
    let max_idle = Duration::from_millis(1500);

    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let server_config =
        tls::server_config_tuned(&bundle, tls::build_transport_config(keep_alive, max_idle)?)?;
    let client_config =
        tls::client_config_tuned(&bundle, tls::build_transport_config(keep_alive, max_idle)?)?;

    let server = echo_server::spawn_echo_server(server_config, "127.0.0.1:0".parse()?).await?;
    let addr = server.addr;

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let conn = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(addr, "localhost")?)
        .await
        .expect("QUIC handshake timed out")?;

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
    assert_eq!(resp.status(), 200);

    let mut buf = BytesMut::new();

    async fn ping_pong(
        stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
        buf: &mut BytesMut,
        payload: &[u8],
    ) -> Result<()> {
        stream.send_data(grpc::encode_frame(payload)).await?;
        loop {
            if let Some(frame) = grpc::take_frame(buf) {
                assert_eq!(&frame[..], payload, "echo mismatch");
                return Ok(());
            }
            match tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
                .await
                .expect("recv_data timed out")?
            {
                Some(mut chunk) => buf.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining())),
                None => panic!("server closed the stream unexpectedly"),
            }
        }
    }

    // First exchange right after connect.
    ping_pong(&mut stream, &mut buf, b"before-idle").await?;

    // ★ Idle far longer than max_idle (1.5s). Without keep-alive the connection
    //   idle-times-out here and the next exchange fails — exactly the device bug.
    tokio::time::sleep(Duration::from_secs(4)).await;

    // If keep-alive kept the connection healthy, this still round-trips.
    ping_pong(&mut stream, &mut buf, b"after-idle").await?;

    stream.finish().await?;
    drive.abort();
    server.task.abort();
    Ok(())
}

/// Diagnostic: does server-only keep-alive keep an idle connection alive when the CLIENT
/// has NO keep-alive (default transport)? This mirrors the device situation where the
/// gateway is confirmed on the keep-alive build but the client app may be linking a stale
/// .a without keep-alive. If this FAILS, the client MUST carry keep-alive too.
#[tokio::test]
async fn server_only_keep_alive_with_idle_client() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let keep_alive = Duration::from_millis(300);
    let max_idle = Duration::from_millis(1500);

    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    // Server: keep-alive ON.
    let server_config =
        tls::server_config_tuned(&bundle, tls::build_transport_config(keep_alive, max_idle)?)?;
    // Client: keep-alive OFF (idle timeout only, no PINGs) — emulates a stale client .a.
    let mut client_tc = quinn::TransportConfig::default();
    client_tc.keep_alive_interval(None);
    client_tc.max_idle_timeout(Some(max_idle.try_into()?));
    let client_config = tls::client_config_tuned(&bundle, std::sync::Arc::new(client_tc))?;

    let server = echo_server::spawn_echo_server(server_config, "127.0.0.1:0".parse()?).await?;
    let addr = server.addr;

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let conn = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(addr, "localhost")?)
        .await
        .expect("QUIC handshake timed out")?;
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
    assert_eq!(resp.status(), 200);

    let mut buf = BytesMut::new();
    stream.send_data(grpc::encode_frame(b"before-idle")).await?;
    loop {
        if grpc::take_frame(&mut buf).is_some() {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
            .await
            .expect("recv_data timed out")?
        {
            Some(mut c) => buf.extend_from_slice(&c.copy_to_bytes(c.remaining())),
            None => panic!("closed early"),
        }
    }

    tokio::time::sleep(Duration::from_secs(4)).await;

    // Try a round-trip after idle. Returns Ok(true) if the connection survived.
    stream.send_data(grpc::encode_frame(b"after-idle")).await?;
    let survived = loop {
        if grpc::take_frame(&mut buf).is_some() {
            break true;
        }
        match tokio::time::timeout(Duration::from_secs(3), stream.recv_data()).await {
            Ok(Ok(Some(mut c))) => buf.extend_from_slice(&c.copy_to_bytes(c.remaining())),
            _ => break false,
        }
    };

    drive.abort();
    server.task.abort();
    println!("SERVER-ONLY keep-alive, idle client survived idle: {survived}");
    Ok(())
}
