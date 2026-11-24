//! A received gRPC message has a length limit.
//!
//! The length prefix is the peer's word, up to 4 GiB, and until 2026-11-24 the client buffered
//! towards whatever it said. The limit is the one the H2 path already enforces on iOS
//! (grpc-swift-nio-transport, 4 MiB), so a message one carrier delivers is never refused by the
//! other.

use std::time::Duration;

use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use construct_transport::{client::QuicClient, grpc, tls};
use http::Response;

const LIMIT: usize = 4 * 1024 * 1024;

/// A server that answers every request with `payload` verbatim and then holds the stream open.
fn raw_server(payload: Bytes) -> Result<(u16, Vec<u8>, quinn::Endpoint)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();
    let endpoint = quinn::Endpoint::server(tls::server_config(&bundle)?, "127.0.0.1:0".parse()?)?;
    let port = endpoint.local_addr()?.port();
    let accept = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accept.accept().await {
            let payload = payload.clone();
            tokio::spawn(async move {
                let conn = h3_quinn::Connection::new(incoming.await.unwrap());
                let mut h3: h3::server::Connection<_, Bytes> =
                    h3::server::Connection::new(conn).await.unwrap();
                while let Ok(Some(resolver)) = h3.accept().await {
                    let payload = payload.clone();
                    tokio::spawn(async move {
                        let (_req, mut stream) = resolver.resolve_request().await.unwrap();
                        stream
                            .send_response(Response::builder().status(200).body(()).unwrap())
                            .await
                            .unwrap();
                        let _ = stream.send_data(payload).await;
                        std::future::pending::<()>().await;
                    });
                }
            });
        }
    });
    Ok((port, cert, endpoint))
}

fn header(len: u32) -> BytesMut {
    let mut b = BytesMut::new();
    b.put_u8(0);
    b.put_u32(len);
    b
}

async fn within<T>(fut: impl std::future::Future<Output = T>, what: &str) -> T {
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .unwrap_or_else(|_| panic!("{what} never resolved"))
}

#[tokio::test]
async fn a_message_declared_over_the_limit_is_refused_before_it_is_buffered() -> Result<()> {
    // A good message, then a header one byte over, with the first of its bytes.
    let mut payload = BytesMut::from(&grpc::encode_frame(b"before")[..]);
    payload.extend_from_slice(&header(LIMIT as u32 + 1));
    payload.extend_from_slice(&[7; 100]);
    let (port, cert, _server) = raw_server(payload.freeze())?;

    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let (_tx, mut rx) = client.open_stream("/x/y", &[]).await?.split();
    assert_eq!(rx.recv_response().await?, 200);

    assert_eq!(
        within(rx.recv_message(), "the good message")
            .await?
            .as_deref(),
        Some(&b"before"[..]),
        "what came before the oversized message is still delivered"
    );
    // Twice: a refused stream must stay refused, not resume inside the body it would not read.
    for _ in 0..2 {
        let text = format!(
            "{:#}",
            within(rx.recv_message(), "the oversized message")
                .await
                .expect_err("over the limit")
        );
        assert!(
            text.contains("4194305") && text.contains("4194304"),
            "{text}"
        );
        assert!(
            !text.contains("h3: closed"),
            "a refusal must not read as our own close: {text}"
        );
    }

    // The call is lost, the connection is not.
    let (_tx2, mut rx2) = client.open_stream("/x/y", &[]).await?.split();
    assert_eq!(within(rx2.recv_response(), "a second call").await?, 200);
    assert_eq!(
        within(rx2.recv_message(), "a second call")
            .await?
            .as_deref(),
        Some(&b"before"[..])
    );
    Ok(())
}

#[tokio::test]
async fn the_unsplit_stream_has_the_same_limit() -> Result<()> {
    let (port, cert, _server) = raw_server(header(u32::MAX).freeze())?;
    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let mut stream = client.open_stream("/x/y", &[]).await?;
    assert_eq!(stream.recv_response().await?, 200);
    assert!(
        within(stream.recv_message(), "the oversized message")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn a_message_of_exactly_the_limit_is_delivered() -> Result<()> {
    let body = vec![5u8; LIMIT];
    let (port, cert, _server) = raw_server(grpc::encode_frame(&body))?;
    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let (_tx, mut rx) = client.open_stream("/x/y", &[]).await?.split();
    assert_eq!(rx.recv_response().await?, 200);
    let got = within(rx.recv_message(), "the largest allowed message")
        .await?
        .expect("a message");
    assert!(got == body, "{} bytes", got.len());
    Ok(())
}
