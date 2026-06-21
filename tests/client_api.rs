//! Phase 1 (Part A) gate: the reusable `QuicClient` API does a bidi gRPC call
//! end-to-end against the echo server. This is the core the UniFFI surface and
//! the Swift `ClientTransport` adapter will wrap.

use anyhow::Result;
use construct_transport::{client::QuicClient, echo_server, tls};

#[tokio::test]
async fn quic_client_bidi_roundtrip() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ── echo server ─────────────────────────────────────────────────────────
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();
    let server_config = tls::server_config(&bundle)?;
    let server = echo_server::spawn_echo_server(server_config, "127.0.0.1:0".parse()?).await?;
    let port = server.addr.port();

    // ── client via the public API ───────────────────────────────────────────
    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let mut stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;

    assert_eq!(stream.recv_response().await?, 200);

    for i in 0..3u32 {
        let payload = format!("msg-{i}").into_bytes();
        stream.send_message(&payload).await?;
        let echoed = stream
            .recv_message()
            .await?
            .expect("expected an echoed message");
        assert_eq!(echoed, payload, "echo mismatch on message {i}");
    }

    stream.finish().await?;
    while stream.recv_message().await?.is_some() {}
    let trailers = stream.recv_trailers().await?;
    if let Some((_, status)) = trailers.iter().find(|(k, _)| k == "grpc-status") {
        assert_eq!(status, "0", "grpc-status should be OK");
    }

    server.task.abort();
    Ok(())
}
