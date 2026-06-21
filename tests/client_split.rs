//! Phase 1 (Part A) gate: the split send/recv halves run full-duplex from two
//! tasks — the concurrency model the UniFFI surface and the Swift
//! `ClientTransport` adapter rely on for `MessageStream`.

use anyhow::Result;
use construct_transport::{client::QuicClient, echo_server, tls};

#[tokio::test]
async fn quic_client_split_full_duplex() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();
    let server_config = tls::server_config(&bundle)?;
    let server = echo_server::spawn_echo_server(server_config, "127.0.0.1:0".parse()?).await?;
    let port = server.addr.port();

    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;
    let (mut send, mut recv) = stream.split();

    assert_eq!(recv.recv_response().await?, 200);

    // Sender runs on its own task while we receive concurrently.
    let sender = tokio::spawn(async move {
        for i in 0..3u32 {
            send.send_message(format!("m{i}").as_bytes()).await.unwrap();
        }
        send.finish().await.unwrap();
    });

    for i in 0..3u32 {
        let msg = recv.recv_message().await?.expect("expected a message");
        assert_eq!(msg, format!("m{i}").into_bytes(), "mismatch on message {i}");
    }

    sender.await?;
    server.task.abort();
    Ok(())
}
