//! Time, wakeups and gateway half of the resource audit. Ordinary allocator.

mod stand;

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use construct_transport::client::QuicClient;
use construct_transport::ffi::QuicChannel;
use construct_transport::{grpc, salamander::Salamander, tls};
use rand::RngCore;
use stand::{Peer, me, usage};

struct Tag;

/// Five repeats, median and spread, of ns per op.
fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    for _ in 0..iters / 4 {
        f();
    }
    let mut r: Vec<f64> = (0..5)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            t.elapsed().as_nanos() as f64 / iters as f64
        })
        .collect();
    r.sort_by(f64::total_cmp);
    println!("{name:<44} {:>12.0} ns  ({:.0}–{:.0})", r[2], r[0], r[4]);
}

fn micro() {
    println!("## micro: ns per operation, median of 5 (min–max)");
    for (size, n) in [
        (128usize, 200_000u32),
        (1024, 50_000),
        (4096, 20_000),
        (65_536, 2_000),
        (1 << 20, 100),
    ] {
        let body = vec![3u8; size];
        let frame = grpc::encode_frame(&body);
        bench(&format!("memcpy baseline {size}"), n, || {
            black_box(black_box(&body).to_vec());
        });
        bench(&format!("encode_frame {size}"), n, || {
            black_box(grpc::encode_frame(black_box(&body)));
        });
        bench(
            &format!("take_frame + to_vec {size} (incl. 1 copy in)"),
            n,
            || {
                let mut b = BytesMut::from(&frame[..]);
                black_box(grpc::take_frame(&mut b).unwrap().unwrap().to_vec());
            },
        );
        bench(
            &format!("uniffi lower Option<Vec<u8>> {size} (incl. 1 copy)"),
            n,
            || {
                let v = Some(body.clone());
                black_box(<Option<Vec<u8>> as uniffi::Lower<Tag>>::lower(v).destroy_into_vec());
            },
        );
        bench(
            &format!("  same bytes, one reserved copy {size}"),
            n,
            || {
                let v = body.clone();
                let mut w = Vec::with_capacity(v.len() + 5);
                w.push(1);
                w.extend_from_slice(&(v.len() as i32).to_be_bytes());
                w.extend_from_slice(&v);
                black_box(w);
            },
        );
        let mut wire = (size as i32).to_be_bytes().to_vec();
        wire.extend_from_slice(&body);
        bench(
            &format!("uniffi lift Vec<u8> {size} (incl. 1 copy)"),
            n,
            || {
                black_box(
                    <Vec<u8> as uniffi::Lift<Tag>>::try_lift(uniffi::RustBuffer::from_vec(
                        wire.clone(),
                    ))
                    .unwrap(),
                );
            },
        );
        bench(&format!("  same bytes, one copy out {size}"), n, || {
            let w = wire.clone();
            black_box(w[4..].to_vec());
        });
    }
    println!("## salamander, one 1200 B datagram");
    let s = Salamander::new(vec![9; 32]);
    let plain = vec![1u8; 1200];
    bench("send path as in obf_socket (rng+vec+obf)", 50_000, || {
        let mut salt = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut buf = vec![0u8; plain.len() + 8];
        s.obfuscate(black_box(&plain), salt, &mut buf);
        black_box(buf);
    });
    let mut wire = vec![0u8; 1208];
    s.obfuscate(&plain, [3; 8], &mut wire);
    let mut scratch = wire.clone();
    bench("deobfuscate in place", 50_000, || {
        scratch.copy_from_slice(&wire);
        black_box(s.deobfuscate_in_place(&mut scratch, 1208));
    });
    bench("  of which memcpy", 50_000, || {
        scratch.copy_from_slice(black_box(&wire));
    });
    bench("  of which key (obfuscate, empty body)", 50_000, || {
        let mut o = [0u8; 8];
        black_box(s.obfuscate(&[], [3; 8], &mut o));
    });
}

/// 64 MiB pushed at us in 4 KiB messages: client process CPU, our socket vs quinn's own.
async fn bulk() -> Result<()> {
    println!("## bulk receive, 64 MiB of 4 KiB messages: CPU of the client process only");
    let peer = Peer::spawn(&["h3"])?;
    let n = 16_384;
    let path = format!("/push/{n}/4096");
    for round in 0..6 {
        let ours =
            QuicClient::connect("127.0.0.1", peer.port, "localhost", peer.cert.clone()).await?;
        let (u, t) = (me(), Instant::now());
        let (_tx, mut rx) = ours.open_stream(&path, &[]).await?.split();
        rx.recv_response().await?;
        let mut got = 0u32;
        while rx.recv_message().await?.is_some() {
            got += 1;
        }
        assert_eq!(got, n);
        println!(
            "round {round} SpinFree socket: cpu {:>7} us  wall {:>6} ms  instr {:>5} M  {}",
            me().cpu_us - u.cpu_us,
            t.elapsed().as_millis(),
            (me().instructions - u.instructions) / 1_000_000,
            ours.stats_string()
        );
        ours.close();

        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        ep.set_default_client_config(tls::client_config(&tls::CertBundle {
            cert: peer.cert.clone().into(),
            key_der: vec![],
        })?);
        let conn = ep
            .connect(format!("127.0.0.1:{}", peer.port).parse()?, "localhost")?
            .await?;
        let (mut drv, mut sr) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await?;
        let dt = tokio::spawn(async move { std::future::poll_fn(|cx| drv.poll_close(cx)).await });
        let (u, t) = (me(), Instant::now());
        let mut st = sr
            .send_request(http::Request::post(format!("https://localhost{path}")).body(())?)
            .await?;
        st.recv_response().await?;
        let mut rb = BytesMut::new();
        let mut got = 0u32;
        while let Some(mut c) = st.recv_data().await? {
            use bytes::Buf;
            let b: Bytes = c.copy_to_bytes(c.remaining());
            rb.extend_from_slice(&b);
            while let Some(f) = grpc::take_frame(&mut rb)? {
                black_box(f.to_vec());
                got += 1;
            }
        }
        assert_eq!(got, n);
        println!(
            "round {round} quinn socket   : cpu {:>7} us  wall {:>6} ms  instr {:>5} M",
            me().cpu_us - u.cpu_us,
            t.elapsed().as_millis(),
            (me().instructions - u.instructions) / 1_000_000
        );
        conn.close(0u32.into(), b"");
        dt.abort();
        ep.close(0u32.into(), b"");
    }
    Ok(())
}

async fn chan(p: &Peer) -> Result<Arc<QuicChannel>> {
    QuicChannel::connect(
        "127.0.0.1".into(),
        p.port,
        "localhost".into(),
        p.cert.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// The same push as the Swift probe, without UniFFI: what the layers below it cost.
async fn recv() -> Result<()> {
    println!(
        "## receive per message, client process: h3 client alone, then through the FFI object (no lowering)"
    );
    let peer = Peer::spawn(&["h3"])?;
    for (size, n) in [
        (128usize, 4000i64),
        (1024, 4000),
        (4096, 4000),
        (65_536, 1000),
        (1 << 20, 60),
    ] {
        for run in 0..3 {
            let path = format!("/push/{n}/{size}");
            let c =
                QuicClient::connect("127.0.0.1", peer.port, "localhost", peer.cert.clone()).await?;
            let (_tx, mut rx) = c.open_stream(&path, &[]).await?.split();
            rx.recv_response().await?;
            let u = me();
            while rx.recv_message().await?.is_some() {}
            let v = me();
            c.close();
            let f = chan(&peer).await?;
            let st = f.open_stream(path, vec![]).await.unwrap();
            st.recv_response().await.unwrap();
            let u2 = me();
            while st.recv_message().await.unwrap().is_some() {}
            let v2 = me();
            f.close();
            println!(
                "{size:>8} run{run}  client: cpu {:>8} ns instr {:>9}/msg   ffi object: cpu {:>8} ns instr {:>9}/msg",
                (v.cpu_us - u.cpu_us) * 1000 / n,
                (v.instructions - u.instructions) / n,
                (v2.cpu_us - u2.cpu_us) * 1000 / n,
                (v2.instructions - u2.instructions) / n
            );
        }
    }
    Ok(())
}

/// `close()` while the caller still holds its handle.
async fn closed_held() -> Result<()> {
    use construct_transport::ffi::{runtime_alive_tasks, transport_runtime_stats};
    let peer = Peer::spawn(&["h3"])?;
    let c = chan(&peer).await?;
    c.close();
    drop(c);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let u0 = me();
    let mut held = vec![];
    for _ in 0..20 {
        let c = chan(&peer).await?;
        c.close();
        held.push(c);
    }
    for w in [4u64, 35] {
        tokio::time::sleep(Duration::from_secs(w)).await;
        println!(
            "20 channels closed, handles held, +{w}s: fds {:+} tasks {} | {}",
            me().fds - u0.fds,
            runtime_alive_tasks(),
            transport_runtime_stats()
        );
    }
    drop(held);
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!(
        "handles dropped, +1s: fds {:+} tasks {}",
        me().fds - u0.fds,
        runtime_alive_tasks()
    );
    Ok(())
}

async fn idle_row(name: &str, secs: u64) {
    let u = me();
    tokio::time::sleep(Duration::from_secs(secs)).await;
    let v = me();
    println!(
        "{name:<40} {secs}s: wakeups {:>4}  cpu {:>6} us  threads {}",
        v.wakeups - u.wakeups,
        v.cpu_us - u.cpu_us,
        v.threads
    );
}

async fn idle() -> Result<()> {
    println!("## idle: wakeups and CPU of the client process");
    let peer = Peer::spawn(&["h3"])?;
    let s = 60;
    idle_row("A: no runtime yet", s).await;
    idle_row("A': no runtime yet (A/A)", s).await;
    let c = chan(&peer).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    idle_row("B: one connection, no stream", s).await;
    let st = c.open_stream("/hold".into(), vec![]).await.unwrap();
    st.recv_response().await.unwrap();
    let st2 = st.clone();
    let park = tokio::spawn(async move {
        let _ = st2.recv_message().await;
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    idle_row("C: connection + stream parked in recv", s).await;
    println!("   {}", c.connection_stats().await.unwrap());
    let more: Vec<_> = vec![chan(&peer).await?, chan(&peer).await?];
    tokio::time::sleep(Duration::from_secs(3)).await;
    idle_row("D: three connections", s).await;
    for m in &more {
        m.close();
    }
    c.close();
    let _ = park.await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    idle_row("E: after close() of all", s).await;
    Ok(())
}

fn kids(name: &str, g: &Peer, up: &Peer, u0: &stand::Usage, v0: &stand::Usage) {
    let (u, v) = (usage(g.pid()), usage(up.pid()));
    println!(
        "{name:<46} gateway: fds {:+} footprint {:+} KB | upstream: fds {:+}",
        u.fds - u0.fds,
        u.footprint_kb - u0.footprint_kb,
        v.fds - v0.fds
    );
}

async fn gateway() -> Result<()> {
    let up = Peer::spawn(&["h2c"])?;
    let g = Peer::spawn(&["role-gateway", &format!("127.0.0.1:{}", up.port)])?;
    let mk = || QuicClient::connect("127.0.0.1", g.port, "localhost", g.cert.clone());
    {
        // warm-up
        let c = mk().await?;
        let (mut tx, mut rx) = c.open_stream("/push/1/128", &[]).await?.split();
        tx.finish().await?;
        rx.recv_response().await?;
        while rx.recv_message().await?.is_some() {}
        c.close();
    }
    tokio::time::sleep(Duration::from_secs(4)).await;

    println!("## gateway: 1000 sequential unary-shaped calls on one client connection");
    for _ in 0..3 {
        let c = mk().await?;
        let (u, t) = (usage(g.pid()), Instant::now());
        for _ in 0..1000 {
            let (mut tx, mut rx) = c.open_stream("/push/1/128", &[]).await?.split();
            tx.finish().await?;
            rx.recv_response().await?;
            while rx.recv_message().await?.is_some() {}
        }
        let v = usage(g.pid());
        println!(
            "through gateway: {:.0} us/call wall, gateway cpu {:.0} us/call, {} K instr/call",
            t.elapsed().as_micros() as f64 / 1000.,
            (v.cpu_us - u.cpu_us) as f64 / 1000.,
            (v.instructions - u.instructions) / 1_000_000
        );
        c.close();
        // the same upstream work over one reused h2c connection
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", up.port)).await?;
        tcp.set_nodelay(true)?;
        let (mut s, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tcp),
        )
        .await?;
        let h = tokio::spawn(conn);
        for fresh in [false, true] {
            let (u, t) = (me(), Instant::now());
            for _ in 0..1000 {
                use http_body_util::{BodyExt, Empty};
                let req = http::Request::post("http://u/push/1/128").body(Empty::<Bytes>::new())?;
                if fresh {
                    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", up.port)).await?;
                    tcp.set_nodelay(true)?;
                    let (mut s, conn) = hyper::client::conn::http2::handshake(
                        hyper_util::rt::TokioExecutor::new(),
                        hyper_util::rt::TokioIo::new(tcp),
                    )
                    .await?;
                    let h = tokio::spawn(conn);
                    black_box(s.send_request(req).await?.into_body().collect().await?);
                    drop(s);
                    let _ = h.await;
                } else {
                    black_box(s.send_request(req).await?.into_body().collect().await?);
                }
            }
            println!(
                "  upstream leg alone, {}: {:.0} us/call wall, {:.0} us/call cpu",
                if fresh {
                    "dial per call (as gateway)"
                } else {
                    "one connection, multiplexed"
                },
                t.elapsed().as_micros() as f64 / 1000.,
                (me().cpu_us - u.cpu_us) as f64 / 1000.
            );
        }
        h.abort();
    }

    for path in ["/hold", "/beat/1000"] {
        println!("## gateway: what is left after 50 clients vanish; upstream stream is {path}");
        tokio::time::sleep(Duration::from_secs(4)).await;
        let (u0, v0) = (usage(g.pid()), usage(up.pid()));
        let mut cs = vec![];
        for _ in 0..50 {
            let c = mk().await?;
            let (tx, mut rx) = c.open_stream(path, &[]).await?.split();
            rx.recv_response().await?;
            rx.recv_message().await?;
            cs.push((c, tx, rx));
        }
        kids("50 clients, one stream each", &g, &up, &u0, &v0);
        for (c, ..) in &cs {
            c.close();
        }
        drop(cs);
        for w in [1u64, 4, 10, 45] {
            tokio::time::sleep(Duration::from_secs(w)).await;
            kids(&format!("  clients closed, +{w}s"), &g, &up, &u0, &v0);
        }
    }

    println!("## gateway: client that never reads, upstream pushes 256 MiB");
    for n in [1usize, 5] {
        tokio::time::sleep(Duration::from_secs(4)).await;
        let (u0, v0) = (usage(g.pid()), usage(up.pid()));
        let mut cs = vec![];
        for _ in 0..n {
            let c = mk().await?;
            let (tx, mut rx) = c.open_stream("/push/4096/65536", &[]).await?.split();
            rx.recv_response().await?;
            cs.push((c, tx, rx));
        }
        for w in [2u64, 5] {
            tokio::time::sleep(Duration::from_secs(w)).await;
            kids(&format!("{n} stalled client(s), +{w}s"), &g, &up, &u0, &v0);
        }
        for (c, ..) in &cs {
            c.close();
        }
    }
    println!("## gateway: one client, 100 streams never read, upstream pushes 256 MiB each");
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (u0, v0) = (usage(g.pid()), usage(up.pid()));
    let c = mk().await?;
    let mut ss = vec![];
    for _ in 0..100 {
        let (tx, mut rx) = c.open_stream("/push/4096/65536", &[]).await?.split();
        let _ = tokio::time::timeout(Duration::from_secs(5), rx.recv_response()).await;
        ss.push((tx, rx));
    }
    for w in [2u64, 5] {
        tokio::time::sleep(Duration::from_secs(w)).await;
        kids(&format!("  +{w}s"), &g, &up, &u0, &v0);
    }
    c.close();
    drop(ss);

    println!("## gateway: 1 GiB read as fast as it comes, one stream");
    for _ in 0..3 {
        let c = mk().await?;
        let (_tx, mut rx) = c.open_stream("/push/16384/65536", &[]).await?.split();
        rx.recv_response().await?;
        let (u, t) = (usage(g.pid()), Instant::now());
        let mut got = 0usize;
        while let Some(m) = rx.recv_message().await? {
            got += m.len();
        }
        println!(
            "{:.0} MB/s, gateway cpu {} ms",
            got as f64 / 1e6 / t.elapsed().as_secs_f64(),
            (usage(g.pid()).cpu_us - u.cpu_us) / 1000
        );
        c.close();
    }

    println!("## gateway: connections that do nothing");
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (u0, v0) = (usage(g.pid()), usage(up.pid()));
    let mut cs = vec![];
    let mut refused = 0;
    for _ in 0..400 {
        match mk().await {
            Ok(c) => cs.push(c),
            Err(_) => refused += 1,
        }
    }
    println!("400 asked: {} in, {refused} refused", cs.len());
    kids("  ", &g, &up, &u0, &v0);
    for c in &cs {
        c.close();
    }

    println!("## gateway: one stream, no call, a HEADERS frame of 1 GiB of which 256 MiB is sent");
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (u0, v0) = (usage(g.pid()), usage(up.pid()));
    let trust = tls::CertBundle {
        cert: g.cert.clone().into(),
        key_der: vec![],
    };
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    ep.set_default_client_config(tls::client_config(&trust)?);
    let conn = ep
        .connect(([127, 0, 0, 1], g.port).into(), "localhost")?
        .await?;
    let (mut tx, _rx) = conn.open_bi().await?;
    tx.write_all(&[0x01, 0xc0, 0, 0, 0, 0x40, 0, 0, 0]).await?;
    let chunk = vec![0u8; 64 * 1024];
    let mut sent = 0;
    while sent < 256 * 1024 * 1024 {
        match tx.write(&chunk).await {
            Ok(n) => sent += n,
            Err(e) => {
                println!("refused after {} KiB: {e}", sent / 1024);
                break;
            }
        }
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    kids("  ", &g, &up, &u0, &v0);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let _ = rustls::crypto::ring::default_provider().install_default();
    if stand::run_role(&args).await? {
        return Ok(());
    }
    match args.first().map(String::as_str).unwrap_or("") {
        "micro" => micro(),
        "bulk" => bulk().await?,
        "recv" => recv().await?,
        "closed-held" => closed_held().await?,
        "idle" => idle().await?,
        "gateway" => gateway().await?,
        other => anyhow::bail!("unknown scenario {other:?}"),
    }
    Ok(())
}
