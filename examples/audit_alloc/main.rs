//! Allocation half of the resource audit. Timing lives in `audit_time`: the counter perturbs it.

#[path = "../audit_time/stand.rs"]
mod stand;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering::Relaxed};
use std::time::Duration;

use anyhow::Result;
use bytes::BytesMut;
use construct_transport::client::QuicClient;
use construct_transport::ffi::{QuicChannel, runtime_alive_tasks};
use construct_transport::{grpc, salamander::Salamander};
use stand::{Peer, me, settle};

struct Counting;
static CALLS: AtomicI64 = AtomicI64::new(0);
static BYTES: AtomicI64 = AtomicI64::new(0);
static LIVE: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicI64 = AtomicI64::new(0);
static ON: AtomicBool = AtomicBool::new(false);

fn add(n: usize) {
    if ON.load(Relaxed) {
        CALLS.fetch_add(1, Relaxed);
        BYTES.fetch_add(n as i64, Relaxed);
    }
    let l = LIVE.fetch_add(n as i64, Relaxed) + n as i64;
    PEAK.fetch_max(l, Relaxed);
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        add(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        add(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as i64, Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_sub(l.size() as i64, Relaxed);
        add(n);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Counting = Counting;

#[derive(Debug)]
struct Count {
    calls: f64,
    bytes: f64,
    peak: i64,
    kept: i64,
}
fn begin() -> i64 {
    CALLS.store(0, Relaxed);
    BYTES.store(0, Relaxed);
    let l = LIVE.load(Relaxed);
    PEAK.store(l, Relaxed);
    ON.store(true, Relaxed);
    l
}
fn end(l0: i64, per: usize) -> Count {
    ON.store(false, Relaxed);
    Count {
        calls: CALLS.load(Relaxed) as f64 / per as f64,
        bytes: BYTES.load(Relaxed) as f64 / per as f64,
        peak: PEAK.load(Relaxed) - l0,
        kept: LIVE.load(Relaxed) - l0,
    }
}
fn live() -> i64 {
    LIVE.load(Relaxed)
}

struct Tag;
const SIZES: [usize; 5] = [128, 1024, 4096, 65_536, 1_048_576];

fn micro() {
    println!("## micro: one operation, allocations / bytes requested");
    for size in SIZES {
        let body = vec![3u8; size];
        let l = begin();
        let f = grpc::encode_frame(&body);
        let enc = end(l, 1);
        let mut rb = BytesMut::from(&f[..]);
        let l = begin();
        let v = grpc::take_frame(&mut rb).unwrap().to_vec();
        let take = end(l, 1);
        let some: Option<Vec<u8>> = Some(v);
        let l = begin();
        let buf = <Option<Vec<u8>> as uniffi::Lower<Tag>>::lower(some);
        let low = end(l, 1);
        let wire = buf.destroy_into_vec();
        let l = begin();
        let mut ideal = Vec::with_capacity(wire.len());
        ideal.extend_from_slice(&wire);
        let id = end(l, 1);
        drop(ideal);
        let rbuf = uniffi::RustBuffer::from_vec(wire[1..].to_vec());
        let l = begin();
        let back = <Vec<u8> as uniffi::Lift<Tag>>::try_lift(rbuf).unwrap();
        let lift = end(l, 1);
        drop(back);
        println!(
            "{size:>8}  encode {:>3}/{:>8}  take+to_vec {:>3}/{:>8}  ffi-lower {:>3}/{:>8}  (ideal {}/{})  ffi-lift {:>3}/{:>8}",
            enc.calls,
            enc.bytes,
            take.calls,
            take.bytes,
            low.calls,
            low.bytes,
            id.calls,
            id.bytes,
            lift.calls,
            lift.bytes
        );
    }
    let s = Salamander::new(vec![9; 32]);
    let plain = vec![1u8; 1200];
    let l = begin();
    let mut out = vec![0u8; plain.len() + 8];
    s.obfuscate(&plain, [1; 8], &mut out);
    println!("salamander send path, 1200 B datagram: {:?}", end(l, 1));
}

async fn push(peer: &Peer) -> Result<()> {
    println!("## receive path below FFI (QuicRecvStream), per message");
    for (size, n) in [
        (128, 4000),
        (1024, 4000),
        (4096, 2000),
        (65_536, 400),
        (1_048_576, 40),
    ] {
        for run in 0..2 {
            let c =
                QuicClient::connect("127.0.0.1", peer.port, "localhost", peer.cert.clone()).await?;
            let s = c.open_stream(&format!("/push/{n}/{size}"), &[]).await?;
            let (_tx, mut rx) = s.split();
            rx.recv_response().await?;
            let l = begin();
            let mut got = 0;
            while let Some(m) = rx.recv_message().await? {
                assert_eq!(m.len(), size);
                got += 1;
            }
            let k = end(l, n);
            assert_eq!(got, n);
            println!(
                "{size:>8} run{run}  calls/msg {:>8.2}  bytes/msg {:>10.0}  x payload {:>5.2}  peak {:>8}  kept {:>8}",
                k.calls,
                k.bytes,
                k.bytes / size as f64,
                k.peak,
                k.kept
            );
            c.close();
        }
    }
    println!("## echo round trip below FFI, per message");
    for (size, n) in [
        (128, 2000),
        (1024, 2000),
        (4096, 1000),
        (65_536, 200),
        (1_048_576, 20),
    ] {
        let c = QuicClient::connect("127.0.0.1", peer.port, "localhost", peer.cert.clone()).await?;
        let (mut tx, mut rx) = c.open_stream("/echo", &[]).await?.split();
        rx.recv_response().await?;
        let body = vec![5u8; size];
        let l = begin();
        for _ in 0..n {
            tx.send_message(&body).await?;
            rx.recv_message().await?.unwrap();
        }
        let k = end(l, n);
        println!(
            "{size:>8}  calls/msg {:>8.2}  bytes/msg {:>10.0}  x payload {:>5.2}  kept {:>8}",
            k.calls,
            k.bytes,
            k.bytes / size as f64,
            k.kept
        );
        c.close();
    }
    Ok(())
}

async fn retain(peer: &Peer) -> Result<()> {
    println!("## memory per connection / per stream / after one large message");
    let l0 = live();
    let c = QuicClient::connect("127.0.0.1", peer.port, "localhost", peer.cert.clone()).await?;
    settle().await;
    let l1 = live();
    println!("one connection, heap held: {} B", l1 - l0);
    let mut held = vec![];
    for _ in 0..50 {
        let (tx, mut rx) = c.open_stream("/hold", &[]).await?.split();
        rx.recv_response().await?;
        held.push((tx, rx));
    }
    settle().await;
    println!(
        "one open stream, heap held: {} B (of 50)",
        (live() - l1) / 50
    );
    drop(held);
    c.close();
    drop(c);
    settle().await;

    let c = QuicClient::connect("127.0.0.1", peer.port, "localhost", peer.cert.clone()).await?;
    let (mut tx, mut rx) = c.open_stream("/echo", &[]).await?.split();
    rx.recv_response().await?;
    tx.send_message(&[1; 128]).await?;
    rx.recv_message().await?;
    settle().await;
    let before = live();
    let big = vec![1; 4 << 20];
    let (sent, got) = tokio::join!(tx.send_message(&big), rx.recv_message());
    sent?;
    drop((got?, big));
    settle().await;
    println!(
        "stream after one 4 MiB message was delivered and dropped: +{} B",
        live() - before
    );
    for _ in 0..50 {
        tx.send_message(&[1; 128]).await?;
        rx.recv_message().await?;
    }
    settle().await;
    println!("… and after 50 more 128 B messages: +{} B", live() - before);
    c.close();
    Ok(())
}

async fn lie(peer: &Peer) -> Result<()> {
    println!("## a peer that declares a huge message (length prefix is never bounded)");
    let c = QuicClient::connect("127.0.0.1", peer.port, "localhost", peer.cert.clone()).await?;
    for mib in [16usize, 64, 256] {
        let (_tx, mut rx) = c
            .open_stream(&format!("/lie/{}/{}", u32::MAX, mib << 20), &[])
            .await?
            .split();
        rx.recv_response().await?;
        let l = begin();
        let r = tokio::time::timeout(Duration::from_secs(8), rx.recv_message()).await;
        let k = end(l, 1);
        println!(
            "peer sent {mib} MiB of a 4 GiB message: result={} held {} MiB, peak {} MiB",
            if r.is_err() {
                "still waiting"
            } else {
                "returned"
            },
            k.kept >> 20,
            k.peak >> 20
        );
    }
    c.close();
    Ok(())
}

async fn chan(p: &Peer) -> Result<std::sync::Arc<QuicChannel>> {
    QuicChannel::connect(
        "127.0.0.1".into(),
        p.port,
        "localhost".into(),
        p.cert.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))
}

async fn reconnect(peer: &Peer) -> Result<()> {
    println!("## 100 reconnects through the FFI object: heap / threads / fds / tasks");
    for mode in [
        "close, nothing held",
        "close, stream parked in recv",
        "drop only",
    ] {
        // warm-up: the runtime, rustls tables, allocator pools
        for _ in 0..3 {
            let c = chan(peer).await?;
            c.close();
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
        let (l0, u0) = (live(), me());
        println!(
            "[{mode}] start: threads {} fds {} footprint {} KB tasks {}",
            u0.threads,
            u0.fds,
            u0.footprint_kb,
            runtime_alive_tasks()
        );
        for i in 1..=100 {
            let c = chan(peer).await?;
            if mode.contains("parked") {
                let s = c.open_stream("/hold".into(), vec![]).await.unwrap();
                s.recv_response().await.unwrap();
                let s2 = s.clone();
                tokio::spawn(async move {
                    let _ = s2.recv_message().await;
                });
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            if mode.starts_with("close") {
                c.close();
            }
            drop(c);
            if i == 1 || i == 10 || i == 100 {
                let u = me();
                println!(
                    "  after {i:>3}, at once: heap {:+} B threads {} fds {} footprint {:+} KB tasks {}",
                    live() - l0,
                    u.threads,
                    u.fds,
                    u.footprint_kb - u0.footprint_kb,
                    runtime_alive_tasks()
                );
            }
        }
        for wait in [1u64, 3, 6, 30] {
            tokio::time::sleep(Duration::from_secs(wait)).await;
            let u = me();
            println!(
                "  +{wait}s: heap {:+} B threads {} fds {} footprint {:+} KB tasks {}",
                live() - l0,
                u.threads,
                u.fds,
                u.footprint_kb - u0.footprint_kb,
                runtime_alive_tasks()
            );
        }
    }
    Ok(())
}

async fn abandoned(peer: &Peer) -> Result<()> {
    println!("## streams abandoned on a live connection, caller releases its handle");
    for (path, parked) in [
        ("/hold", true),
        ("/hold", false),
        ("/beat/200", true),
        ("/beat/200", false),
    ] {
        let c = chan(peer).await?;
        let t0 = runtime_alive_tasks();
        let l0 = live();
        let mut opened = 0;
        let mut stuck = "no";
        for _ in 0..300 {
            let open =
                tokio::time::timeout(Duration::from_secs(5), c.open_stream(path.into(), vec![]))
                    .await;
            let Ok(Ok(s)) = open else {
                stuck = if open.is_err() {
                    "hangs (5 s)"
                } else {
                    "error"
                };
                break;
            };
            opened += 1;
            s.recv_response().await.unwrap();
            if parked {
                let _ = tokio::time::timeout(Duration::from_millis(5), async {
                    while let Ok(Some(_)) = s.recv_message().await {}
                })
                .await;
            }
            drop(s);
        }
        settle().await;
        println!(
            "[server {path}, receive parked: {parked}] opened {opened}/300, next open: {stuck}, tasks {} (was {t0}), heap {:+} B",
            runtime_alive_tasks(),
            live() - l0
        );
        c.close();
    }
    Ok(())
}

async fn lost(peer: &Peer) -> Result<()> {
    println!("## a receive the caller cancelled: does the next receive still see the message?");
    let c = chan(peer).await?;
    let s = c.open_stream("/echo".into(), vec![]).await.unwrap();
    s.recv_response().await.unwrap();
    let r = tokio::time::timeout(Duration::from_millis(50), s.recv_message()).await;
    assert!(r.is_err());
    s.send_message(b"one".to_vec()).await.unwrap();
    s.send_message(b"two".to_vec()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), s.recv_message()).await;
    println!(
        "sent one, two; next receive got {:?}",
        got.map(|r| r.unwrap().map(|b| String::from_utf8(b).unwrap()))
    );
    c.close();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let _ = rustls::crypto::ring::default_provider().install_default();
    if stand::run_role(&args).await? {
        return Ok(());
    }
    let peer = Peer::spawn(&["h3"])?;
    match args.first().map(String::as_str).unwrap_or("") {
        "micro" => micro(),
        "push" => push(&peer).await?,
        "retain" => retain(&peer).await?,
        "lie" => lie(&peer).await?,
        "reconnect" => reconnect(&peer).await?,
        "abandoned" => abandoned(&peer).await?,
        "lost" => lost(&peer).await?,
        other => anyhow::bail!("unknown scenario {other:?}"),
    }
    Ok(())
}
