//! The gateway is a public, unauthenticated UDP endpoint on the host that runs the server. What one
//! peer can make it hold must be bounded by the gateway, not by the peer.

use std::convert::Infallible;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, Bytes};
use construct_transport::{h3_guard, proxy, tls};
use http::{Request, Response};
use http_body_util::{BodyExt, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;

const MIB: usize = 1024 * 1024;

#[derive(Default)]
struct Upstream {
    /// Bytes the upstream managed to hand over for `/push`.
    pushed: AtomicUsize,
    /// h2 connections from the gateway: open now, and ever.
    open: AtomicUsize,
    dialed: AtomicUsize,
    /// Starts every `/gate` that is waiting.
    gate: tokio::sync::Notify,
}

/// `/push` writes for as long as it is read, `/gate` does so after a signal, `/hold` answers
/// headers and neither reads nor writes, anything else echoes.
async fn upstream() -> Result<(String, Arc<Upstream>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    let state = Arc::new(Upstream::default());
    let shared = state.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let state = shared.clone();
            tokio::spawn(async move {
                state.open.fetch_add(1, Ordering::SeqCst);
                state.dialed.fetch_add(1, Ordering::SeqCst);
                let for_calls = state.clone();
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    // Little, so that what is taken is taken by the gateway.
                    .initial_stream_window_size(64 * 1024)
                    .initial_connection_window_size(64 * 1024)
                    .serve_connection(
                        TokioIo::new(tcp),
                        service_fn(move |req| call(req, for_calls.clone())),
                    )
                    .await;
                state.open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok((addr, state))
}

async fn call(
    req: Request<Incoming>,
    state: Arc<Upstream>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
    let path = req.uri().path().to_owned();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(1);
    let body = match path.as_str() {
        "/push" | "/gate" => {
            tokio::spawn(async move {
                if path == "/gate" {
                    state.gate.notified().await;
                }
                let chunk = Bytes::from(vec![7u8; 16 * 1024]);
                while tx.send(Ok(Frame::data(chunk.clone()))).await.is_ok() {
                    state.pushed.fetch_add(chunk.len(), Ordering::SeqCst);
                }
            });
            StreamBody::new(ReceiverStream::new(rx)).boxed()
        }
        "/hold" => {
            tokio::spawn(async move {
                let _unread = req.into_body();
                tx.closed().await;
            });
            StreamBody::new(ReceiverStream::new(rx)).boxed()
        }
        _ => req.into_body().boxed(),
    };
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(body)
        .unwrap())
}

struct Stand {
    gw: proxy::ProxyHandle,
    up: Arc<Upstream>,
    client: quinn::Endpoint,
    client_config: quinn::ClientConfig,
}

async fn stand() -> Result<Stand> {
    stand_with(proxy::Limits::default()).await
}

async fn stand_with(limits: proxy::Limits) -> Result<Stand> {
    let (addr, up) = upstream().await?;
    stand_on(addr, up, limits).await
}

async fn stand_on(addr: String, up: Arc<Upstream>, limits: proxy::Limits) -> Result<Stand> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bundle = tls::self_signed(vec!["localhost".into()])?;
    let config = tls::server_config(&bundle)?;
    let gw = proxy::serve_with_limits(config, "127.0.0.1:0".parse()?, addr, limits).await?;

    // A client that grants the gateway little, so that what is held is held by the gateway.
    let mut tc = quinn::TransportConfig::default();
    tc.stream_receive_window((64 * 1024u32).into());
    tc.keep_alive_interval(Some(Duration::from_secs(1)));
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    let client_config = tls::client_config_tuned(&bundle, Arc::new(tc))?;
    client.set_default_client_config(client_config.clone());
    Ok(Stand {
        gw,
        up,
        client,
        client_config,
    })
}

impl Stand {
    async fn connect(&self) -> Result<quinn::Connection> {
        let connecting = self.client.connect(self.gw.addr, "localhost")?;
        Ok(tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("handshake neither finished nor was refused")?)
    }
}

type SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type Call = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn h3_client(conn: quinn::Connection) -> Result<SendRequest> {
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    Ok(send)
}

async fn open(send: &mut SendRequest, path: &str) -> Result<Call> {
    let req = Request::builder()
        .method("POST")
        .uri(format!("https://localhost{path}"))
        .header("content-type", "application/grpc+proto")
        .body(())?;
    Ok(send.send_request(req).await?)
}

/// Keep writing until the peer refuses, `limit` is reached, or nothing moves for two seconds.
async fn pour(stream: &mut quinn::SendStream, limit: usize) -> (usize, Option<String>) {
    let chunk = vec![0u8; 64 * 1024];
    let mut sent = 0;
    while sent < limit {
        match tokio::time::timeout(Duration::from_secs(2), stream.write(&chunk)).await {
            Ok(Ok(n)) => sent += n,
            Ok(Err(e)) => return (sent, Some(e.to_string())),
            Err(_) => break,
        }
    }
    (sent, None)
}

/// The peer is told why: `H3_EXCESSIVE_LOAD`.
fn assert_excessive_load(conn: &quinn::Connection) {
    match conn.close_reason() {
        Some(quinn::ConnectionError::ApplicationClosed(close)) => {
            assert_eq!(close.error_code.into_inner(), 0x107)
        }
        other => panic!("{other:?}"),
    }
}

/// Send on every call until each is stuck; bytes sent in all. The calls stay open to the end.
async fn pour_all(calls: Vec<Call>) -> Result<usize> {
    let mut pumps = vec![];
    for mut call in calls {
        pumps.push(tokio::spawn(async move {
            let chunk = Bytes::from(vec![0u8; 64 * 1024]);
            let mut sent = 0;
            while sent < 64 * MIB {
                let write = call.send_data(chunk.clone());
                match tokio::time::timeout(Duration::from_secs(2), write).await {
                    Ok(Ok(())) => sent += chunk.len(),
                    _ => break,
                }
            }
            (sent, call)
        }));
    }
    let mut total = 0;
    let mut held = vec![];
    for pump in pumps {
        let (sent, call) = pump.await?;
        total += sent;
        held.push(call);
    }
    Ok(total)
}

/// QUIC varint, the eight-byte form.
fn varint8(v: u64) -> [u8; 8] {
    (v | 0xc000_0000_0000_0000).to_be_bytes()
}

/// h3 keeps a frame other than DATA whole before it looks at it, so its length is the peer's
/// choice unless somebody reads the length first. No authentication happens before this point.
#[tokio::test]
async fn a_huge_headers_frame_is_refused_not_collected() -> Result<()> {
    let s = stand().await?;
    let conn = s.connect().await?;
    let (mut send, _recv) = conn.open_bi().await?;
    send.write_all(&[0x01]).await?; // HEADERS
    send.write_all(&varint8(1 << 30)).await?;
    let (sent, refused) = pour(&mut send, 64 * MIB).await;
    assert!(refused.is_some(), "gateway took {} MiB", sent / MIB);
    assert!(sent < 4 * MIB, "gateway took {sent} bytes before refusing");
    assert_excessive_load(&conn);
    Ok(())
}

/// The same on the control stream, which h3 reads for the whole life of the connection.
#[tokio::test]
async fn a_huge_control_frame_is_refused_not_collected() -> Result<()> {
    let s = stand().await?;
    let conn = s.connect().await?;
    let mut control = conn.open_uni().await?;
    control.write_all(&[0x00]).await?; // stream type: control
    control.write_all(&[0x04]).await?; // SETTINGS
    control.write_all(&varint8(1 << 30)).await?;
    let (sent, refused) = pour(&mut control, 64 * MIB).await;
    assert!(refused.is_some(), "gateway took {} MiB", sent / MIB);
    assert!(sent < 4 * MIB, "gateway took {sent} bytes before refusing");
    assert_excessive_load(&conn);
    Ok(())
}

/// A client that asks for data and does not read it. What the upstream managed to hand over is
/// what the gateway (and the kernel's loopback buffers) took on the client's behalf.
#[tokio::test]
async fn a_reader_that_stalls_does_not_fill_the_gateway() -> Result<()> {
    let s = stand().await?;
    let mut send = h3_client(s.connect().await?).await?;
    let mut held = vec![];
    for _ in 0..8 {
        let mut call = open(&mut send, "/push").await?;
        call.recv_response().await?;
        held.push(call);
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let first = s.up.pushed.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let settled = s.up.pushed.load(Ordering::SeqCst);
    assert_eq!(first, settled, "still filling");
    eprintln!(
        "8 stalled calls: upstream handed over {} KiB",
        settled / 1024
    );
    assert!(settled < 2 * MIB, "gateway took {} KiB", settled / 1024);
    Ok(())
}

/// The other direction: an upstream that does not read, a client that keeps sending on many calls.
#[tokio::test]
async fn an_upload_nobody_reads_does_not_fill_the_gateway() -> Result<()> {
    let s = stand().await?;
    let conn = s.connect().await?;
    let mut send = h3_client(conn.clone()).await?;
    let mut calls = vec![];
    for _ in 0..8 {
        let mut call = open(&mut send, "/hold").await?;
        call.recv_response().await?;
        calls.push(call);
    }
    let total = pour_all(calls).await?;
    eprintln!("8 unread uploads: the gateway took {} KiB", total / 1024);
    assert!(total < 5 * MIB / 2, "gateway took {} KiB", total / 1024);
    Ok(())
}

/// An upstream process that grants h2 credit and then stops reading its socket: what is left is the
/// gateway's own send buffer and the kernel's.
#[tokio::test]
async fn a_wedged_upstream_does_not_fill_the_gateway() -> Result<()> {
    use tokio::io::AsyncWriteExt;
    // The kernel's share is not the gateway's: keep it small. Linux sizes the sender's buffer by
    // ten segments, and a loopback segment is 64 KiB.
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(16 * 1024)?;
    let segment: libc::c_int = 1000;
    unsafe {
        libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(&socket),
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            (&raw const segment).cast(),
            size_of_val(&segment) as libc::socklen_t,
        );
    }
    socket.bind("127.0.0.1:0".parse()?)?;
    let listener = socket.listen(16)?;
    let addr = listener.local_addr()?.to_string();
    tokio::spawn(async move {
        let mut wedged = vec![];
        while let Ok((mut tcp, _)) = listener.accept().await {
            // SETTINGS { INITIAL_WINDOW_SIZE: 1 GiB }, WINDOW_UPDATE { 1 GiB } on the connection.
            let hello = [
                0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0x40, 0, 0, 0, //
                0, 0, 4, 8, 0, 0, 0, 0, 0, 0x40, 0, 0, 0,
            ];
            tcp.write_all(&hello).await.unwrap();
            wedged.push(tcp);
        }
    });
    let s = stand_on(addr, Arc::default(), proxy::Limits::default()).await?;
    let mut send = h3_client(s.connect().await?).await?;
    let mut calls = vec![];
    for _ in 0..8 {
        calls.push(open(&mut send, "/any").await?);
    }
    let total = pour_all(calls).await?;
    eprintln!(
        "8 uploads to a wedged upstream: {} KiB left the client",
        total / 1024
    );
    assert!(total < 5 * MIB, "gateway took {} KiB", total / 1024);
    Ok(())
}

/// One stuck upload stops itself and nothing else on its connection.
#[tokio::test]
async fn a_stuck_upload_does_not_stop_the_next_call() -> Result<()> {
    let s = stand().await?;
    let mut send = h3_client(s.connect().await?).await?;
    let mut stuck = open(&mut send, "/hold").await?;
    stuck.recv_response().await?;
    let chunk = Bytes::from(vec![0u8; 64 * 1024]);
    let mut sent = 0;
    while let Ok(wrote) =
        tokio::time::timeout(Duration::from_secs(1), stuck.send_data(chunk.clone())).await
    {
        wrote?;
        sent += chunk.len();
        assert!(sent < 4 * MIB, "the upload is not stuck");
    }
    let next = async {
        open(&mut send, "/hold")
            .await?
            .recv_response()
            .await
            .map_err(anyhow::Error::from)
    };
    let response = tokio::time::timeout(Duration::from_secs(3), next)
        .await
        .expect("the next call never got through")?;
    assert_eq!(response.status(), 200);
    Ok(())
}

/// h3 alone reads up to two chunks for every DATA frame it hands out: with frames of three bytes
/// that is a kilobyte kept for every byte passed on. A reader that takes 2000 of them and stops.
#[tokio::test]
async fn tiny_data_frames_do_not_pile_up_behind_the_reader() -> Result<()> {
    const WINDOW: u32 = 64 * 1024;
    const READS: usize = 2000;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bundle = tls::self_signed(vec!["localhost".into()])?;
    let mut tc = quinn::TransportConfig::default();
    tc.receive_window(WINDOW.into());
    tc.stream_receive_window(WINDOW.into());
    let server = quinn::Endpoint::server(
        tls::server_config_tuned(&bundle, Arc::new(tc))?,
        "127.0.0.1:0".parse()?,
    )?;
    let addr = server.local_addr()?;
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let guarded = h3_guard::Connection::new(conn);
        let mut h3 = h3::server::Connection::<_, Bytes>::new(guarded)
            .await
            .unwrap();
        let call = h3.accept().await.unwrap().unwrap();
        let (_req, mut stream) = call.resolve_request().await.unwrap();
        // Slower than the peer, as a reader is whose own way out is the bottleneck.
        for i in 0..READS {
            if i % 10 == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            stream.recv_data().await.unwrap().unwrap();
        }
        std::future::pending::<()>().await;
    });

    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(tls::client_config(&bundle)?);
    let conn = client.connect(addr, "localhost")?.await?;
    let (mut send, _recv) = conn.open_bi().await?;
    send.write_all(&raw_headers("/any")).await?;
    let frames = [0x00, 0x01, 0x07].repeat(20 * 1024);
    let mut sent = 0;
    while let Ok(n) = tokio::time::timeout(Duration::from_secs(1), send.write(&frames)).await {
        sent += n?;
    }
    // Read by the reader, plus one window, plus the chunk being cut, plus the request.
    let allowed = 3 * READS + WINDOW as usize + 4 * 1024;
    assert!(
        sent <= allowed,
        "took {sent}, the reader asked for {allowed}"
    );
    Ok(())
}

/// A request written by hand (QPACK static table, RFC 9204 appendix A), so that the frames after
/// it can be whatever the test needs.
fn raw_headers(path: &str) -> Vec<u8> {
    let mut block = vec![0, 0, 0xc0 | 20, 0xc0 | 23]; // :method POST, :scheme https
    for (name, value) in [(0u8, "localhost"), (1, path)] {
        block.push(0x50 | name);
        block.push(value.len() as u8);
        block.extend_from_slice(value.as_bytes());
    }
    let mut out = vec![0x01, block.len() as u8];
    out.extend(block);
    out
}

/// The limits are for frames that are kept. Headers of a real size, one DATA frame of 3 MiB (three
/// times the connection window), and the answer come through whole.
#[tokio::test]
async fn honest_traffic_larger_than_the_windows_passes() -> Result<()> {
    let s = stand().await?;
    let mut send = h3_client(s.connect().await?).await?;
    let req = Request::builder()
        .method("POST")
        .uri("https://localhost/echo")
        .header("content-type", "application/grpc+proto")
        .header("x-long", "a".repeat(8 * 1024))
        .body(())?;
    let (mut tx, mut rx) = send.send_request(req).await?.split();
    let payload: Vec<u8> = (0..3 * MIB).map(|i| (i % 251) as u8).collect();
    let body = Bytes::from(payload.clone());
    let sender = tokio::spawn(async move {
        tx.send_data(body).await?;
        tx.finish().await
    });
    let work = async {
        rx.recv_response().await?;
        let mut got = Vec::with_capacity(payload.len());
        while let Some(mut chunk) = rx.recv_data().await? {
            let n = chunk.remaining();
            got.extend_from_slice(&chunk.copy_to_bytes(n));
        }
        anyhow::Ok(got)
    };
    let got = tokio::time::timeout(Duration::from_secs(20), work)
        .await
        .expect("stalled")?;
    sender.await??;
    assert!(got == payload, "got {} bytes", got.len());
    Ok(())
}

/// The refused one learns it at once, the ones inside are not touched, and a slot that is given
/// back is usable.
#[tokio::test]
async fn a_full_gateway_refuses_and_then_admits_again() -> Result<()> {
    let s = stand_with(proxy::Limits {
        max_connections: 2,
        validate_above: usize::MAX,
        ..Default::default()
    })
    .await?;
    let first = s.connect().await?;
    let second = s.connect().await?;

    let asked = std::time::Instant::now();
    let error = s
        .connect()
        .await
        .expect_err("third connection was admitted");
    assert!(error.to_string().contains("refused"), "{error:#}");
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "{:?}",
        asked.elapsed()
    );

    let mut send = h3_client(first).await?;
    open(&mut send, "/hold").await?.recv_response().await?;

    second.close(0u32.into(), b"");
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if s.connect().await.is_ok() {
            return Ok(());
        }
    }
    panic!("the slot was never given back");
}

/// Arriving together does not get anybody past the limit. The gateway runs on a thread of its own,
/// held busy while the attempts arrive, so that it finds them all waiting.
#[tokio::test]
async fn a_burst_does_not_overshoot_the_limit() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let bundle = tls::self_signed(vec!["localhost".into()])?;
    let limits = proxy::Limits {
        max_connections: 3,
        validate_above: usize::MAX,
        ..Default::default()
    };
    let config = tls::server_config(&bundle)?;
    let gw = rt
        .spawn(async move {
            let bind = "127.0.0.1:0".parse().unwrap();
            proxy::serve_with_limits(config, bind, "127.0.0.1:1".into(), limits).await
        })
        .await??;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(tls::client_config(&bundle)?);

    rt.spawn(async { std::thread::sleep(Duration::from_millis(300)) });
    let mut attempts = vec![];
    for _ in 0..40 {
        attempts.push(tokio::spawn(
            client.connect(gw.addr, "localhost")?.into_future(),
        ));
    }
    let mut inside = vec![];
    for attempt in attempts {
        if let Ok(conn) = attempt.await? {
            inside.push(conn);
        }
    }
    let admitted = inside.len();
    rt.shutdown_background();
    assert_eq!(admitted, 3);
    Ok(())
}

/// One byte on the wire can name a 64-byte field, so the limit on the frame is not the limit on
/// what it unpacks to. Such a request does not reach the upstream.
#[tokio::test]
async fn headers_that_unpack_past_the_limit_are_refused() -> Result<()> {
    let s = stand().await?;
    let conn = s.connect().await?;
    let mut block = raw_headers("/hold").split_off(2);
    block.extend([0xc0 | 31].repeat(20_000)); // accept-encoding: gzip, deflate, br
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&[0x01]).await?;
    send.write_all(&(0x8000_0000 | block.len() as u32).to_be_bytes())
        .await?;
    send.write_all(&block).await?;
    let mut answer = [0u8; 1];
    let _ = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut answer))
        .await
        .expect("no answer");
    assert_eq!(
        s.up.dialed.load(Ordering::SeqCst),
        0,
        "request went upstream"
    );
    Ok(())
}

/// Nothing reads QUIC datagrams here, so the gateway does not offer to keep them.
#[tokio::test]
async fn datagrams_are_not_accepted() -> Result<()> {
    let s = stand().await?;
    assert_eq!(s.connect().await?.max_datagram_size(), None);
    Ok(())
}

/// A path to the gateway: counts the Retry packets that come back, and can be cut on the way there.
#[derive(Default)]
struct Path {
    retries: AtomicUsize,
    cut: AtomicBool,
}

async fn path_to(gateway: SocketAddr) -> Result<(SocketAddr, Arc<Path>)> {
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    back.connect(gateway).await?;
    let addr = front.local_addr()?;
    let path = Arc::new(Path::default());
    let seen = path.clone();
    tokio::spawn(async move {
        let (mut a, mut b) = (vec![0u8; 65536], vec![0u8; 65536]);
        let mut peer = None;
        loop {
            tokio::select! {
                Ok((n, from)) = front.recv_from(&mut a) => {
                    peer = Some(from);
                    if !seen.cut.load(Ordering::SeqCst) {
                        let _ = back.send(&a[..n]).await;
                    }
                }
                Ok(n) = back.recv(&mut b) => {
                    // Long header, packet type 3 (RFC 9000 §17.2.5).
                    if b[0] & 0xf0 == 0xf0 {
                        seen.retries.fetch_add(1, Ordering::SeqCst);
                    }
                    if let Some(peer) = peer {
                        let _ = front.send_to(&b[..n], peer).await;
                    }
                }
            }
        }
    });
    Ok((addr, path))
}

/// A client that granted plenty of credit and then stopped acknowledging. What is unacknowledged
/// stays with the gateway.
#[tokio::test]
async fn a_client_that_stops_acknowledging_does_not_fill_the_gateway() -> Result<()> {
    let s = stand().await?;
    let (addr, path) = path_to(s.gw.addr).await?;
    let mut config = s.client_config.clone();
    config.transport_config(Arc::new(quinn::TransportConfig::default()));
    let conn = s.client.connect_with(config, addr, "localhost")?.await?;
    let mut send = h3_client(conn).await?;
    let mut calls = vec![];
    for _ in 0..8 {
        let mut call = open(&mut send, "/gate").await?;
        call.recv_response().await?;
        calls.push(call);
    }
    path.cut.store(true, Ordering::SeqCst);
    s.up.gate.notify_waiters();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let pushed = s.up.pushed.load(Ordering::SeqCst);
    eprintln!(
        "8 calls unacknowledged: upstream handed over {} KiB",
        pushed / 1024
    );
    assert!(pushed > MIB / 2, "nothing was pushed: {pushed}");
    assert!(pushed < 3 * MIB, "gateway took {} KiB", pushed / 1024);
    Ok(())
}

/// Below the threshold nothing changes; at it the peer proves its address and still gets in.
#[tokio::test]
async fn a_busy_gateway_asks_for_the_address_first() -> Result<()> {
    let s = stand_with(proxy::Limits {
        max_connections: 8,
        validate_above: 1,
        ..Default::default()
    })
    .await?;
    let mut held = vec![];
    for expected in [0, 1] {
        let (addr, path) = path_to(s.gw.addr).await?;
        let connecting = s.client.connect(addr, "localhost")?;
        let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("handshake timed out")?;
        assert_eq!(path.retries.load(Ordering::SeqCst), expected);
        let mut send = h3_client(conn.clone()).await?;
        open(&mut send, "/hold").await?.recv_response().await?;
        held.push((conn, send));
    }
    Ok(())
}

/// An upstream that keeps the call open after the client is gone held a TCP connection, an h2
/// connection and a task for as long as it liked. It does not see the end of the request as a
/// reason to finish, which is what `/hold` is.
#[tokio::test]
async fn upstream_calls_do_not_outlive_their_client() -> Result<()> {
    let s = stand_with(proxy::Limits {
        orphan_grace: Duration::from_millis(300),
        ..Default::default()
    })
    .await?;
    let conn = s.connect().await?;
    let mut send = h3_client(conn.clone()).await?;
    let mut held = vec![];
    for _ in 0..5 {
        let mut call = open(&mut send, "/hold").await?;
        call.recv_response().await?;
        held.push(call);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    for call in &mut held {
        let silent = tokio::time::timeout(Duration::from_millis(20), call.recv_data()).await;
        assert!(silent.is_err(), "a live call was dropped");
    }
    conn.close(0u32.into(), b"");
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if s.up.open.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }
    }
    panic!(
        "{} upstream connections left",
        s.up.open.load(Ordering::SeqCst)
    );
}
