//! Salamander obfuscation gate: bidi gRPC-over-HTTP/3 works when BOTH ends apply the same
//! Salamander PSK, and a plain (un-obfuscated) client CANNOT complete the handshake against an
//! obfuscated server — proving the bytes on the wire are transformed (no recognizable QUIC).

use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, BytesMut};
use construct_transport::{echo_server, grpc, obf_socket, salamander::Salamander, tls};
use http::Request;
use quinn::Endpoint;

const PSK: &[u8] = b"salamander-host-test-psk";

#[tokio::test]
async fn obfuscated_bidi_roundtrips_and_plain_client_is_rejected() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let server_config = tls::server_config(&bundle)?;
    let client_config = tls::client_config(&bundle)?;

    // ── obfuscated server ────────────────────────────────────────────────
    let server_ep = obf_socket::obfuscated_server_endpoint(
        "127.0.0.1:0".parse()?,
        Salamander::new(PSK.to_vec()),
        server_config,
    )?;
    let server = echo_server::spawn_echo_on_endpoint(server_ep)?;
    let addr = server.addr;

    // ── obfuscated client (matching PSK) ─────────────────────────────────
    let mut client_ep = obf_socket::obfuscated_client_endpoint(
        "127.0.0.1:0".parse()?,
        Salamander::new(PSK.to_vec()),
    )?;
    client_ep.set_default_client_config(client_config.clone());

    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        client_ep.connect(addr, "localhost")?,
    )
    .await
    .expect("obfuscated QUIC handshake timed out")?;

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
        .expect("recv_response timed out through obfuscation")?;
    assert_eq!(
        resp.status(),
        200,
        "obfuscated path should reach the server"
    );

    let mut buf = BytesMut::new();
    for i in 0..3u32 {
        let payload = format!("obf-msg-{i}").into_bytes();
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
        assert_eq!(&echoed[..], &payload[..], "obfuscated echo mismatch on {i}");
    }
    drive.abort();

    // ── negative: a PLAIN client must NOT be able to handshake the obfuscated server ──
    let mut plain_client = Endpoint::client("127.0.0.1:0".parse()?)?;
    plain_client.set_default_client_config(client_config);
    let plain_result = tokio::time::timeout(
        Duration::from_secs(2),
        plain_client.connect(addr, "localhost")?,
    )
    .await;
    assert!(
        plain_result.is_err() || plain_result.unwrap().is_err(),
        "plain QUIC must NOT complete a handshake against an obfuscated server"
    );

    server.task.abort();
    Ok(())
}
