//! A retired `QuicClient` must leave no connection behind.
//!
//! WHAT THESE DO AND DO NOT PROVE. They were written to confirm a theory about the device heat
//! incident of 2026-08-09 (`cpu=106% hot=[construct-transport:100%]` for as long as the iOS app
//! stayed foregrounded, against 13% on a fresh single-connection session): that abandoned
//! connections accumulated, because a dropped `JoinHandle` detaches rather than cancels, a
//! dropped `Endpoint` does not close its connections, and keep-alive at 15s beats the 30s idle
//! timeout so an orphan can never expire.
//!
//! **The theory did not survive.** Emptying the entire `Drop` body leaves every test here green,
//! including the held-stream case. Dropping the client already closes the connection today. The
//! heat has some other cause, and it is still unidentified.
//!
//! So read these as what they are: a statement that teardown is now explicit rather than a
//! consequence of drop order inside two dependencies, plus a gauge that can test the
//! accumulation theory on a real device instead of against a loopback echo server.

use std::time::Duration;

use anyhow::Result;
use construct_transport::{client::QuicClient, client::live_connections, echo_server, tls};

/// `live_connections()` is process-wide, and the tests in this file all open connections. Cargo
/// runs them in parallel threads of one binary, so without this they read each other's gauge —
/// the first run of `the_live_gauge_returns_to_its_starting_value` failed on exactly that.
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Boot an echo server and return (port, cert, server handle).
async fn echo() -> Result<(u16, Vec<u8>, echo_server::ServerHandle)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();
    let server_config = tls::server_config(&bundle)?;
    let server = echo_server::spawn_echo_server(server_config, "127.0.0.1:0".parse()?).await?;
    Ok((server.addr.port(), cert, server))
}

#[tokio::test]
async fn dropping_a_client_with_no_open_stream_closes_its_connection() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    let (port, cert, server) = echo().await?;

    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    // A clone of the quinn handle survives the drop, so we can ask the connection itself whether
    // it closed — asking the dropped client would prove nothing.
    let observer = client.connection_handle();
    assert!(
        observer.close_reason().is_none(),
        "connection should be healthy while the client is alive"
    );

    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(observer.close_reason().is_some());

    // NOT A REGRESSION GUARD. This case already passed before `Drop` existed: with no stream
    // outstanding, dropping the client drops the last h3 handles and the connection closes on
    // its own. Verified by mutation — emptying the `Drop` body leaves this green. It is kept
    // only to bound the claim below: the leak is about held streams, not about drop in general.
    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn dropping_a_client_while_a_stream_is_held_still_closes_its_connection() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    // THE DEVICE CASE. `QuicClientTransport` parks a receive pump in `recv_message` for the whole
    // life of the MessageStream RPC, then retires the channel by dropping it on reconnect — so
    // the client goes away while a `QuicStream` still holds the h3 halves, and with them the
    // connection. Without an explicit close in `Drop` those handles keep it alive, and keep-alive
    // (15s) beats the idle timeout (30s), so it can never expire on its own.
    let (port, cert, server) = echo().await?;

    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let observer = client.connection_handle();
    let mut stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;
    assert_eq!(stream.recv_response().await?, 200);

    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        observer.close_reason().is_some(),
        "a client dropped while a stream is still held must close its connection anyway — \
         otherwise it survives every reference to it and PINGs itself alive forever"
    );

    // The stream outliving the connection is fine; it fails, which is what a retired channel
    // should do. What must not happen is the connection staying up.
    drop(stream);
    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn an_open_stream_does_not_keep_a_closed_client_alive() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    // The shape that produced the device symptom: a stream parked on recv while the owner walks
    // away. Explicit `close()` exists precisely so this does not depend on the last reference.
    let (port, cert, server) = echo().await?;

    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let observer = client.connection_handle();
    let mut stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;
    assert_eq!(stream.recv_response().await?, 200);

    client.close();
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        observer.close_reason().is_some(),
        "close() must not wait for open streams to be released"
    );

    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn the_live_gauge_returns_to_its_starting_value() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    // Tests share a process, so the gauge is asserted as a delta rather than against zero.
    let before = live_connections();
    let (port, cert, server) = echo().await?;

    {
        let _client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
        assert_eq!(
            live_connections(),
            before + 1,
            "an open connection must be countable — it was invisible while they accumulated"
        );
    }

    assert_eq!(
        live_connections(),
        before,
        "the gauge must fall when a client is dropped, or it cannot show a leak"
    );

    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn an_explicitly_closed_connection_stops_counting_as_live() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    // The device path. iOS retires a channel with `close()` while its receive pump is still
    // parked on the stream, so the `Arc` outlives the connection by however long that takes.
    // Counting until then reports `conns=1` for a connection that is shut, which is
    // indistinguishable from the abandoned-endpoint leak this gauge was added to find.
    let before = live_connections();
    let (port, cert, server) = echo().await?;

    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let mut stream = client.open_stream("/construct.Echo/BiDi", &[]).await?;
    assert_eq!(stream.recv_response().await?, 200);
    assert_eq!(live_connections(), before + 1);

    client.close();

    assert_eq!(
        live_connections(),
        before,
        "closed is not live — the held stream must not keep it on the books"
    );

    drop(stream);
    drop(client);
    assert_eq!(
        live_connections(),
        before,
        "and dropping the closed client must not subtract a second time"
    );

    server.task.abort();
    Ok(())
}
