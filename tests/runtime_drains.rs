//! The transport runtime must go quiet when its last connection goes away.
//!
//! INCIDENT (device, 2026-08-10, iPhone, build 593 + the runtime gauge):
//!
//! ```text
//! 06:59:04  cpu=9.4%    conns=1 tasks=4   ← healthy
//! 06:59:34  cpu=110.5%  conns=0 tasks=1
//! 06:59:54  cpu=107.4%  conns=0 tasks=1   thermal=fair
//! 07:00:04  cpu=107.1%  conns=0 tasks=1
//! ```
//!
//! Zero connections, one task, one full CPU core — for as long as the app stayed foregrounded,
//! with the phone getting hot in the user's hand. Not accumulated connections (`conns=0`), not
//! leaked tasks (`tasks=1`): one task that never yields, and it appears exactly when the
//! connection is torn down (`conns` 1 → 0, `tasks` 4 → 1).
//!
//! These tests go through `QuicChannel` rather than `QuicClient`, because the runtime in question
//! is the FFI layer's static `RT` — a `#[tokio::test]` on `QuicClient` runs on the test's own
//! runtime and would measure nothing.
//!
//! RESULT: all three shapes drain cleanly here. **The device symptom does not reproduce on
//! loopback**, so these are a negative result plus a regression guard, not the fix. What they
//! rule out: teardown of a healthy connection, teardown after an open stream, and a handshake
//! that never completes. What is left is what this harness cannot stage — the real iOS platform,
//! a network interface changing under a live socket, and process suspension.
//!
//! Two caveats worth knowing before trusting a green run. `RT` is shared, so a task leaked by an
//! earlier test raises the baseline of a later one and can mask it; whichever test leaks fails
//! first, which is the ordering that matters. And `baseline` is read after the lock is taken, so
//! it is the count for an idle runtime — if that ever stops being 0, these assertions get weaker
//! without saying so.

use std::time::Duration;

use anyhow::Result;
use construct_transport::{
    client::{QuicClient, live_connections},
    echo_server,
    ffi::{QuicChannel, runtime_alive_tasks},
    tls,
};

/// `RT` is process-wide, like the gauges. Serialise so the tests do not read each other's tasks.
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn echo() -> Result<(u16, Vec<u8>, echo_server::ServerHandle)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();
    let server_config = tls::server_config(&bundle)?;
    let server = echo_server::spawn_echo_server(server_config, "127.0.0.1:0".parse()?).await?;
    Ok((server.addr.port(), cert, server))
}

/// Poll until `alive tasks <= target`, up to `timeout`. Returns the last reading either way.
///
/// Polling rather than a fixed sleep: task teardown is asynchronous, and a fixed sleep either
/// makes the test slow or makes it flaky. A spinning task never drains, so the timeout is only
/// paid when the test is about to fail anyway.
async fn wait_for_tasks(target: usize, timeout: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let alive = runtime_alive_tasks();
        if alive <= target || tokio::time::Instant::now() >= deadline {
            return alive;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn the_runtime_drains_after_the_last_connection_is_dropped() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    let (port, cert, server) = echo().await?;

    let baseline = runtime_alive_tasks();

    let channel =
        QuicChannel::connect("127.0.0.1".to_string(), port, "localhost".to_string(), cert)
            .await
            .map_err(|e| anyhow::anyhow!("connect: {e}"))?;

    assert_eq!(live_connections(), 1, "one connection is open");

    drop(channel);

    let alive = wait_for_tasks(baseline, Duration::from_secs(5)).await;
    assert_eq!(
        live_connections(),
        0,
        "the connection must be gone before the task question is meaningful"
    );
    assert!(
        alive <= baseline,
        "transport runtime did not drain: {alive} task(s) alive, baseline {baseline}. \
         On device this state reads `conns=0 tasks=1` and burns a full CPU core."
    );

    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn the_runtime_drains_after_a_stream_was_used() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    // Closer to the device: the connection carried an open gRPC stream before being retired,
    // which is what MessageStream does. A stream leaves more machinery behind to shut down.
    let (port, cert, server) = echo().await?;

    let baseline = runtime_alive_tasks();

    let channel =
        QuicChannel::connect("127.0.0.1".to_string(), port, "localhost".to_string(), cert)
            .await
            .map_err(|e| anyhow::anyhow!("connect: {e}"))?;

    let stream = channel
        .open_stream("/construct.Echo/BiDi".to_string(), vec![])
        .await
        .map_err(|e| anyhow::anyhow!("open_stream: {e}"))?;
    assert_eq!(
        stream
            .recv_response()
            .await
            .map_err(|e| anyhow::anyhow!("recv_response: {e}"))?,
        200
    );

    drop(stream);
    drop(channel);

    let alive = wait_for_tasks(baseline, Duration::from_secs(5)).await;
    assert!(
        alive <= baseline,
        "transport runtime did not drain after a stream: {alive} alive, baseline {baseline}"
    );

    server.task.abort();
    Ok(())
}

#[tokio::test]
async fn the_runtime_drains_after_a_handshake_that_never_completes() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    // THE DEVICE SHAPE. On the network in question QUIC never got through — the log reads
    // "Fast-UDP disabled — 2 consecutive failures, using H2 direct" and every MessageStream ran
    // over H2 from then on. So `conns=0` is not "the connection was closed", it is "the
    // connection was never established": `QuicClient::connect` binds an endpoint, the handshake
    // times out after HANDSHAKE_TIMEOUT, and the attempt is dropped. That path never touches the
    // connection gauge, which is exactly why the device could report `conns=0 tasks=1`.
    //
    // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): guaranteed unrouted, so the handshake gets no
    // answer rather than a refusal — the blackhole a censored UDP path produces.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();

    let baseline = runtime_alive_tasks();

    let result = QuicChannel::connect(
        "203.0.113.1".to_string(),
        443,
        "localhost".to_string(),
        cert,
    )
    .await;
    assert!(
        result.is_err(),
        "a blackholed handshake must fail, not hang forever"
    );
    assert_eq!(
        live_connections(),
        0,
        "a failed handshake opens no connection"
    );

    let alive = wait_for_tasks(baseline, Duration::from_secs(5)).await;
    assert!(
        alive <= baseline,
        "a failed handshake left {alive} task(s) alive (baseline {baseline}). This is the device \
         state: conns=0 tasks=1 with a worker thread pinned at 100%."
    );

    Ok(())
}

#[tokio::test]
async fn a_refused_udp_port_does_not_leave_the_endpoint_spinning() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    // The mechanism from the device stack, staged the only way loopback can stage it.
    //
    // `the_runtime_drains_after_a_handshake_that_never_completes` uses TEST-NET-3, which drops
    // packets **silently** — no ICMP, no socket error, so it could never have reproduced the spin
    // and its passing proved nothing about this. A *closed* local UDP port is different: the
    // kernel answers with ICMP port-unreachable, which Darwin surfaces as a pending socket error,
    // which is exactly what `quinn_udp::UdpSocketState::recv` was burning a core on.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bundle = tls::self_signed(vec!["localhost".to_string()])?;
    let cert = bundle.cert.as_ref().to_vec();

    // Bind and immediately release a UDP port so nothing is listening on it.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let dead_port = probe.local_addr()?.port();
    drop(probe);

    let baseline = runtime_alive_tasks();

    let result = QuicChannel::connect(
        "127.0.0.1".to_string(),
        dead_port,
        "localhost".to_string(),
        cert,
    )
    .await;
    assert!(
        result.is_err(),
        "nothing is listening — the handshake must fail"
    );

    let alive = wait_for_tasks(baseline, Duration::from_secs(5)).await;
    assert!(
        alive <= baseline,
        "a refused handshake left {alive} task(s) alive (baseline {baseline}) — the endpoint \
         driver is still polling a socket that only ever returns an error"
    );

    // DOES NOT DISCRIMINATE, verified by mutation: stubbing `close_endpoint` out entirely leaves
    // this green (only `dropping_a_client_stops_its_endpoint` goes red). The refused port produces
    // the right kind of socket error, but the task still drains here — whatever keeps the driver
    // alive on device does not happen on loopback. Kept as a guard on the shape, not as evidence
    // that the spin is fixed. Only the device can settle that: `transport=conns=0 tasks=0`.
    Ok(())
}

#[tokio::test]
async fn dropping_a_client_stops_its_endpoint() -> Result<()> {
    let _serialized = TEST_LOCK.lock().await;
    // Direct statement of the fix. `Endpoint::close` makes further connects fail with
    // EndpointStopping; a merely-dropped handle would still accept one, because quinn keeps the
    // endpoint alive independently of who holds a handle to it.
    let (port, cert, server) = echo().await?;

    let client = QuicClient::connect("127.0.0.1", port, "localhost", cert).await?;
    let endpoint = client.endpoint_handle();
    assert!(
        endpoint
            .connect("127.0.0.1:1".parse()?, "localhost")
            .is_ok(),
        "endpoint should still be usable while the client is alive"
    );

    drop(client);

    assert!(
        endpoint
            .connect("127.0.0.1:1".parse()?, "localhost")
            .is_err(),
        "the endpoint must be stopped, not merely unreferenced — its driver is what spun at 100%"
    );

    server.task.abort();
    Ok(())
}
