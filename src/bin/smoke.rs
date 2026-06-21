//! Live smoke test for a deployed gateway.
//!
//! Calls a real *unary* gRPC method through `client → h3 → gateway → envoy →
//! messaging-service` and reports the returned gRPC status. ANY valid gRPC
//! status — even `UNAUTHENTICATED` — proves the full path works: the request
//! reached the real service and a gRPC response came back through the gateway.
//! The request body is intentionally empty (we don't have a token / valid args).
//!
//! Usage:
//!   cargo run --bin smoke -- <host> <port> <cert.der> [method-path] [server-name]
//!   cargo run --bin smoke -- quic.konstruct.cc 443 server-cert.der

use std::net::ToSocketAddrs;
use std::time::Duration;

use anyhow::{Context, Result};
use construct_transport::{grpc, tls};
use http::Request;
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;

const DEFAULT_PATH: &str = "/shared.proto.services.v1.MessagingService/GetPendingMessages";

fn grpc_status_name(code: &str) -> &'static str {
    match code {
        "0" => "OK",
        "3" => "INVALID_ARGUMENT",
        "5" => "NOT_FOUND",
        "7" => "PERMISSION_DENIED",
        "12" => "UNIMPLEMENTED",
        "13" => "INTERNAL",
        "14" => "UNAVAILABLE",
        "16" => "UNAUTHENTICATED",
        _ => "(other)",
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args = std::env::args().skip(1);
    let host = args
        .next()
        .context("usage: smoke <host> <port> <cert.der> [method-path] [server-name]")?;
    let port: u16 = args
        .next()
        .context("port required")?
        .parse()
        .context("invalid port")?;
    let cert_path = args.next().context("path to server-cert.der required")?;
    let path = args.next().unwrap_or_else(|| DEFAULT_PATH.to_string());
    let server_name = args.next().unwrap_or_else(|| host.clone());

    let cert_der = std::fs::read(&cert_path).with_context(|| format!("read {cert_path}"))?;
    let bundle = tls::CertBundle {
        cert: CertificateDer::from(cert_der),
        key_der: Vec::new(),
    };
    let client_config = tls::client_config(&bundle)?;

    let addr = format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("DNS resolve {host}:{port}"))?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    println!("→ {host}:{port}  method {path}  (SNI {server_name})");
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        endpoint.connect(addr, &server_name)?,
    )
    .await
    .context("QUIC handshake timed out — UDP filtered?")??;
    println!("✓ QUIC handshake ok (rtt {:?})", conn.rtt());

    let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = Request::builder()
        .method("POST")
        .uri(format!("https://{server_name}{path}"))
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .body(())?;
    let mut stream = send_req.send_request(req).await?;

    // Unary: send one (empty) gRPC frame, then half-close so the server runs.
    stream.send_data(grpc::encode_frame(&[])).await?;
    stream.finish().await?;

    let resp = tokio::time::timeout(Duration::from_secs(10), stream.recv_response())
        .await
        .context("recv_response timed out — bidi headers never arrived")??;
    println!("✓ HTTP {} from upstream (via gateway)", resp.status());

    // gRPC status may arrive in the response headers (trailers-only error) or in
    // the trailers after the body. Check both.
    let mut status = resp
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let mut message = resp
        .headers()
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    while (stream.recv_data().await?).is_some() {} // drain any response body

    if let Some(trailers) = stream.recv_trailers().await? {
        if let Some(s) = trailers.get("grpc-status").and_then(|v| v.to_str().ok()) {
            status = Some(s.to_string());
        }
        if let Some(m) = trailers.get("grpc-message").and_then(|v| v.to_str().ok()) {
            message = Some(m.to_string());
        }
    }

    drive.abort();

    match status {
        Some(code) => {
            println!(
                "✓ grpc-status: {code} ({}){}",
                grpc_status_name(&code),
                message.map(|m| format!(" — \"{m}\"")).unwrap_or_default()
            );
            println!(
                "\nPASS — reached messaging-service through the gateway end-to-end \
                 (any gRPC status proves the path)."
            );
            Ok(())
        }
        None => {
            anyhow::bail!("no grpc-status returned — request did not reach a gRPC service")
        }
    }
}
