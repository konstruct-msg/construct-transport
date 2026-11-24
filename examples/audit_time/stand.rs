//! Shared half of the resource-audit stand: the peer processes and the process meter.
//!
//! The peer always runs in its **own process**, so the numbers of the measured process contain
//! one side of the connection only. Nothing here changes the product: it drives the public API.
#![allow(dead_code, deprecated)]

use std::convert::Infallible;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use construct_transport::{grpc, proxy, tls};
use http::{HeaderMap, HeaderValue, Request, Response};
use http_body_util::{BodyExt, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio_stream::wrappers::ReceiverStream;

// ── process meter (macOS) ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct Usage {
    pub threads: i64,
    pub fds: i64,
    pub footprint_kb: i64,
    pub cpu_us: i64,
    pub wakeups: i64,
    pub instructions: i64,
}

#[cfg(target_os = "macos")]
pub fn usage(pid: i32) -> Usage {
    use std::mem::{size_of, zeroed};
    unsafe {
        let mut ti: libc::proc_taskinfo = zeroed();
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            (&raw mut ti).cast(),
            size_of::<libc::proc_taskinfo>() as i32,
        );
        let mut ru: libc::rusage_info_v4 = zeroed();
        libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V4, (&raw mut ru).cast());
        const PROC_PIDLISTFDS: i32 = 1;
        let mut fds = vec![0u8; 8 * 8192];
        let n = libc::proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            fds.len() as i32,
        );
        let mut tb: libc::mach_timebase_info = zeroed();
        libc::mach_timebase_info(&mut tb);
        let ns = |t: u64| (t as u128 * tb.numer as u128 / tb.denom as u128) as i64;
        Usage {
            threads: ti.pti_threadnum as i64,
            fds: (n / 8) as i64,
            footprint_kb: (ru.ri_phys_footprint / 1024) as i64,
            cpu_us: (ns(ru.ri_user_time) + ns(ru.ri_system_time)) / 1000,
            wakeups: (ru.ri_pkg_idle_wkups + ru.ri_interrupt_wkups) as i64,
            instructions: ru.ri_instructions as i64,
        }
    }
}

/// The meter is Darwin-only; elsewhere the stand must still compile (CI runs clippy on Linux).
/// It refuses rather than returning zeroes: a row of `fds +0` reads as a measurement.
#[cfg(not(target_os = "macos"))]
pub fn usage(_pid: i32) -> Usage {
    unimplemented!("the process meter is macOS-only")
}

pub fn me() -> Usage {
    usage(std::process::id() as i32)
}

// ── peer processes ───────────────────────────────────────────────────────────

pub struct Peer {
    child: Child,
    pub port: u16,
    pub cert: Vec<u8>,
}

impl Peer {
    pub fn spawn(args: &[&str]) -> Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(args)
            .stdout(Stdio::piped())
            .spawn()?;
        let mut line = String::new();
        BufReader::new(child.stdout.take().context("stdout")?).read_line(&mut line)?;
        let mut it = line.split_whitespace();
        let port = it.next().context("port")?.parse()?;
        let hex = it.next().unwrap_or("");
        let cert = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        Ok(Self { child, port, cert })
    }
    pub fn pid(&self) -> i32 {
        self.child.id() as i32
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn announce(port: u16, cert: &[u8]) {
    let hex: String = cert.iter().map(|b| format!("{b:02x}")).collect();
    println!("{port} {hex}");
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Returns true when argv selected a peer role, which then runs forever.
pub async fn run_role(args: &[String]) -> Result<bool> {
    match args.first().map(String::as_str) {
        Some("h3") => h3_server().await?,
        Some("h2c") => h2c_server().await?,
        Some("role-gateway") => {
            let bundle = tls::self_signed(vec!["localhost".into()])?;
            let h = proxy::serve(
                tls::server_config(&bundle)?,
                "127.0.0.1:0".parse()?,
                args[1].clone(),
            )
            .await?;
            announce(h.addr.port(), bundle.cert.as_ref());
            h.task.await?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// `/echo` · `/push/<count>/<size>` · `/hold` · `/lie/<declared>/<sent>`
async fn h3_server() -> Result<()> {
    let bundle = tls::self_signed(vec!["localhost".into()])?;
    let ep = quinn::Endpoint::server(tls::server_config(&bundle)?, "127.0.0.1:0".parse()?)?;
    announce(ep.local_addr()?.port(), bundle.cert.as_ref());
    while let Some(inc) = ep.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = inc.await else { return };
            let Ok(mut h3) = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await
            else {
                return;
            };
            while let Ok(Some(r)) = h3.accept().await {
                tokio::spawn(async move {
                    let _ = h3_request(r).await;
                });
            }
        });
    }
    Ok(())
}

async fn h3_request(r: h3::server::RequestResolver<h3_quinn::Connection, Bytes>) -> Result<()> {
    let (req, mut s) = r.resolve_request().await?;
    s.send_response(
        Response::builder()
            .status(200)
            .header("content-type", "application/grpc+proto")
            .body(())?,
    )
    .await?;
    let parts: Vec<String> = req.uri().path().split('/').map(str::to_owned).collect();
    match parts.get(1).map(String::as_str) {
        Some("push") => {
            let (n, size): (usize, usize) = (parts[2].parse()?, parts[3].parse()?);
            let frame = grpc::encode_frame(&vec![7u8; size]);
            for _ in 0..n {
                s.send_data(frame.clone()).await?;
            }
        }
        Some("lie") => {
            let (declared, sent): (u32, usize) = (parts[2].parse()?, parts[3].parse()?);
            let mut b = BytesMut::new();
            b.put_u8(0);
            b.put_u32(declared);
            s.send_data(b.freeze()).await?;
            let chunk = Bytes::from(vec![0u8; 64 * 1024]);
            for _ in 0..sent / chunk.len() {
                s.send_data(chunk.clone()).await?;
            }
            std::future::pending::<()>().await;
        }
        // `/hold` says nothing, ever. `/beat/<ms>` sends a frame every <ms> and so notices a
        // cancelled stream, as a server with heartbeats does.
        Some("hold") => std::future::pending::<()>().await,
        Some("beat") => {
            let f = grpc::encode_frame(b"beat");
            loop {
                s.send_data(f.clone()).await?;
                tokio::time::sleep(Duration::from_millis(parts[2].parse()?)).await;
            }
        }
        _ => {
            while let Some(mut c) = s.recv_data().await? {
                let d = c.copy_to_bytes(c.remaining());
                s.send_data(d).await?;
            }
        }
    }
    let mut t = HeaderMap::new();
    t.insert("grpc-status", HeaderValue::from_static("0"));
    s.send_trailers(t).await?;
    s.finish().await?;
    Ok(())
}

async fn h2c_server() -> Result<()> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    announce(l.local_addr()?.port(), &[]);
    loop {
        let (tcp, _) = l.accept().await?;
        tcp.set_nodelay(true).ok();
        tokio::spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tcp), service_fn(h2c_request))
                .await;
        });
    }
}

async fn h2c_request(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let parts: Vec<String> = req.uri().path().split('/').map(str::to_owned).collect();
    let beat: Option<u64> =
        (parts.get(1).map(String::as_str) == Some("beat")).then(|| parts[2].parse().unwrap());
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
    tokio::spawn(async move {
        match parts.get(1).map(String::as_str) {
            Some("push") => {
                let (n, size): (usize, usize) =
                    (parts[2].parse().unwrap(), parts[3].parse().unwrap());
                let f = grpc::encode_frame(&vec![7u8; size]);
                for _ in 0..n {
                    if tx.send(Ok(Frame::data(f.clone()))).await.is_err() {
                        return;
                    }
                }
            }
            // A server stream that says nothing and ignores the client's half-close: what a
            // quiet MessageStream looks like from the gateway.
            Some("beat") => {
                let _body = req.into_body();
                let f = grpc::encode_frame(b"beat");
                while tx.send(Ok(Frame::data(f.clone()))).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(beat.unwrap())).await;
                }
                return;
            }
            Some("hold") => {
                let _body = req.into_body();
                let _ = tx.send(Ok(Frame::data(grpc::encode_frame(b"hello")))).await;
                tx.closed().await;
                return;
            }
            _ => {
                let mut b = req.into_body();
                while let Some(Ok(f)) = b.frame().await {
                    if let Ok(d) = f.into_data()
                        && tx.send(Ok(Frame::data(d))).await.is_err()
                    {
                        return;
                    }
                }
            }
        }
        let mut t = HeaderMap::new();
        t.insert("grpc-status", HeaderValue::from_static("0"));
        let _ = tx.send(Ok(Frame::trailers(t))).await;
    });
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(StreamBody::new(ReceiverStream::new(rx)).boxed())
        .unwrap())
}

pub async fn settle() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}
