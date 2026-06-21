//! Remote reachability probe (Phase 0).
//!
//! Connects to a running construct-transport echo server over QUIC/HTTP-3 and
//! runs one bidi gRPC roundtrip. Use it to confirm QUIC/UDP survives the path
//! from a real client to the VPS *before* building the real h3->envoy gateway.
//!
//! Usage:
//!   cargo run --bin probe -- <host> <port> <server-cert.der> [server-name]
//!   cargo run --bin probe -- quic.konstruct.cc 443 server-cert.der
//!
//! `server-name` defaults to `<host>` and must match the server's cert SAN
//! (QUIC_SAN). The cert is the `server-cert.der` the echo server writes on start.

use std::net::ToSocketAddrs;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::{Buf, BytesMut};
use construct_transport::{grpc, tls};
use http::Request;
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args = std::env::args().skip(1);
    let host = args
        .next()
        .context("usage: probe <host> <port> <cert.der> [server-name]")?;
    let port: u16 = args
        .next()
        .context("port required")?
        .parse()
        .context("invalid port")?;
    let cert_path = args.next().context("path to server-cert.der required")?;
    let server_name = args.next().unwrap_or_else(|| host.clone());

    // Trust exactly the server's self-signed cert (no dangerous "accept any").
    let cert_der = std::fs::read(&cert_path).with_context(|| format!("read {cert_path}"))?;
    let bundle = tls::CertBundle {
        cert: CertificateDer::from(cert_der),
        key_der: Vec::new(), // client side: private key unused
    };
    let client_config = tls::client_config(&bundle)?;

    let addr = format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("DNS resolve {host}:{port}"))?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    println!("→ connecting QUIC to {addr} (SNI: {server_name})");
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        endpoint.connect(addr, &server_name)?,
    )
    .await
    .context("QUIC handshake timed out — UDP is likely filtered on the path")??;
    println!("✓ QUIC handshake ok (rtt {:?})", conn.rtt());

    let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!("https://{server_name}/construct.Echo/BiDi"))
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .body(())?;
    let mut stream = send_req.send_request(req).await?;

    // The gate: response HEADERS must arrive on the bidi stream.
    let resp = tokio::time::timeout(Duration::from_secs(10), stream.recv_response())
        .await
        .context("recv_response timed out — bidi headers never arrived")??;
    println!("✓ response headers: HTTP {}", resp.status());
    if resp.status() != 200 {
        bail!("unexpected status {}", resp.status());
    }

    let mut buf = BytesMut::new();
    for i in 0..3u32 {
        let payload = format!("probe-{i}").into_bytes();
        stream.send_data(grpc::encode_frame(&payload)).await?;
        let echoed = loop {
            if let Some(frame) = grpc::take_frame(&mut buf) {
                break frame;
            }
            match tokio::time::timeout(Duration::from_secs(10), stream.recv_data())
                .await
                .context("recv_data timed out")??
            {
                Some(mut chunk) => buf.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining())),
                None => bail!("server closed before echo {i}"),
            }
        };
        if echoed[..] != payload[..] {
            bail!("echo mismatch on frame {i}");
        }
        println!("✓ bidi echo {i} ok");
    }

    stream.finish().await?;
    drive.abort();
    println!("\nPASS — bidi gRPC-over-HTTP/3 reaches {host}:{port} end-to-end.");
    Ok(())
}
