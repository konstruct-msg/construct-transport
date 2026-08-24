//! A network handover must cost a QUIC connection nothing.
//!
//! Device, 2026-08-24 (`construct-logs-1787564712`): connected in 85ms at 09:43:19; wifi→cellular
//! at 09:43:26; from there `rx_pkts` sat frozen at 16 while `tx_pkts` climbed to 47, and at
//! 09:44:01 the recv pump timed out and QUIC was disabled for the rest of the session. The
//! connection was addressable the whole time — QUIC identifies a connection by connection ID, not
//! by four-tuple — but nothing told quinn the local address had moved, so it kept sending from a
//! socket whose source address no longer routed.
//!
//! `QuicClient::rebind` is the missing signal. What these tests pin is not that
//! `rebind_abstract` was called — that would pass with the socket swapped and the connection dead
//! — but that a live H3 stream still carries data afterwards, and that a rebind which the peer
//! cannot answer is *reported* rather than silently left to the 30s idle timeout.

use std::time::Duration;

use anyhow::Result;
use construct_transport::{client::QuicClient, echo_server, salamander::Salamander, tls};

/// The property, on a real connection: swap the socket under a stream that is mid-conversation and
/// the conversation continues.
///
/// The stream is opened and exercised *before* the rebind so that what survives is a connection
/// with state on it, not a fresh one that happens to work. The loopback address does not change,
/// but the port does, and the port is what the peer's four-tuple is keyed on — so from the
/// server's side this is the same event as a handover: datagrams for a known connection ID
/// arriving from somewhere new.
#[tokio::test]
async fn a_live_stream_survives_the_socket_being_replaced() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();
    let server = echo_server::spawn_echo_server(tls::server_config(&bundle)?, "127.0.0.1:0".parse()?)
        .await?;

    let client = QuicClient::connect("127.0.0.1", server.addr.port(), "localhost", cert).await?;
    let mut stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;
    assert_eq!(stream.recv_response().await?, 200);

    stream.send_message(b"before-handover").await?;
    assert_eq!(
        stream.recv_message().await?.expect("echo before rebind"),
        b"before-handover"
    );

    let before = client.endpoint_handle().local_addr()?;
    let after = tokio::time::timeout(Duration::from_secs(5), client.rebind())
        .await
        .expect("rebind hung")?;
    assert_ne!(
        before, after,
        "a rebind that kept the same local address migrated nothing"
    );

    // The point of the whole exercise: the same stream, not a new one.
    stream.send_message(b"after-handover").await?;
    assert_eq!(
        stream.recv_message().await?.expect("echo after rebind"),
        b"after-handover",
        "the stream died at the handover — this is the 2026-08-24 device log"
    );

    server.task.abort();
    Ok(())
}

/// The same on an obfuscated connection, which is where the replacement socket can be built wrong
/// in a way nothing reports.
///
/// A plain socket rebound under a Salamander connection sends every datagram in the clear to a
/// gateway that discards them as garbage. There is no error anywhere in that path — the connection
/// simply stops — and it stops during a handover, which is exactly when a connection stopping
/// looks unremarkable. `client_socket` is one builder for both the first socket and the
/// replacement so the two cannot disagree; this is the test that would notice if they did.
#[tokio::test]
async fn an_obfuscated_connection_migrates_with_its_obfuscation() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    const PSK: &[u8] = b"rebind-migration-test-psk";

    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();
    let server_ep = construct_transport::obf_socket::obfuscated_server_endpoint(
        "127.0.0.1:0".parse()?,
        Salamander::new(PSK.to_vec()),
        tls::server_config_obf(&bundle)?,
    )?;
    let server = echo_server::spawn_echo_on_endpoint(server_ep)?;

    let client = QuicClient::connect_obfuscated(
        "127.0.0.1",
        server.addr.port(),
        "localhost",
        cert,
        PSK.to_vec(),
    )
    .await?;
    let mut stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;
    assert_eq!(stream.recv_response().await?, 200);

    tokio::time::timeout(Duration::from_secs(5), client.rebind())
        .await
        .expect("obfuscated rebind hung")?;

    stream.send_message(b"obf-after-handover").await?;
    assert_eq!(
        stream.recv_message().await?.expect("echo after obf rebind"),
        b"obf-after-handover",
        "the replacement socket did not carry the connection's obfuscation"
    );

    server.task.abort();
    Ok(())
}

/// A migration the peer cannot answer must come back as an error, not as silence.
///
/// This is the whole reason `rebind` returns a verdict instead of just swapping the socket. The
/// caller's fallback — throw the connection away and open a new one — always works, so a rebind
/// that reported success on the swap alone would trade an immediate reconnect for a 30s idle
/// timeout on the one path this feature exists to improve.
///
/// Staged by closing the server endpoint before the swap. **What that does and does not cover:**
/// it puts the connection into the "peer is gone" state, so the verdict comes from `close_reason`
/// rather than from the budget expiring. A peer that goes silent without closing — the real
/// handover failure — cannot be staged here, because `ServerHandle::task.abort()` stops only the
/// accept loop and the per-connection tasks it already spawned keep answering. Both branches are
/// one `if` apart in `rebind`; this pins that a failed migration is reported at all, which is the
/// property the caller's decision rests on.
#[tokio::test]
async fn a_migration_the_peer_cannot_answer_is_reported() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();
    let server = echo_server::spawn_echo_server(tls::server_config(&bundle)?, "127.0.0.1:0".parse()?)
        .await?;

    let client = QuicClient::connect("127.0.0.1", server.addr.port(), "localhost", cert).await?;
    let mut stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;
    assert_eq!(stream.recv_response().await?, 200);

    server.task.abort();
    server.endpoint.close(0u32.into(), b"gone");
    // Let the CONNECTION_CLOSE arrive before the socket is swapped.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = tokio::time::timeout(Duration::from_secs(5), client.rebind())
        .await
        .expect("rebind must give up on its own budget, not hang");
    assert!(
        result.is_err(),
        "an unanswered migration reported success — the caller would now wait out the idle timeout"
    );

    Ok(())
}
