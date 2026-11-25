//! TLS / certificate plumbing for the Phase 0 spike.
//!
//! Generates a self-signed cert (rcgen) and builds quinn client/server configs
//! with the `h3` ALPN. The client trusts exactly the spike's own cert, so we
//! avoid a dangerous "accept any cert" verifier even in tests.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
};

/// HTTP/3 ALPN identifier — required on both ends of a QUIC/H3 handshake.
pub const ALPN_H3: &[u8] = b"h3";

/// A self-signed certificate plus its PKCS#8 private key (DER bytes).
pub struct CertBundle {
    pub cert: CertificateDer<'static>,
    /// PKCS#8-encoded private key, DER bytes.
    pub key_der: Vec<u8>,
}

/// Generate a fresh self-signed certificate for the given SAN names.
pub fn self_signed(names: Vec<String>) -> Result<CertBundle> {
    let certified = rcgen::generate_simple_self_signed(names)?;
    let cert = certified.cert.der().clone();
    let key_der = certified.key_pair.serialize_der();
    Ok(CertBundle { cert, key_der })
}

/// Load a persistent cert+key pair (DER) from disk, or generate a fresh self-signed
/// pair for `names` and write it to those paths.
///
/// This keeps the gateway certificate **stable across restarts** so clients can pin it
/// once. Both files must be present to reuse an existing pair — the old gateway wrote
/// only the cert (the key was ephemeral), so a cert-without-key is regenerated. Persist
/// the paths on a mounted volume; otherwise the container's filesystem resets the pair.
pub fn load_or_generate(
    names: Vec<String>,
    cert_path: &Path,
    key_path: &Path,
) -> Result<CertBundle> {
    if cert_path.exists() && key_path.exists() {
        let cert = CertificateDer::from(
            fs::read(cert_path).with_context(|| format!("read cert {}", cert_path.display()))?,
        );
        let key_der =
            fs::read(key_path).with_context(|| format!("read key {}", key_path.display()))?;
        return Ok(CertBundle { cert, key_der });
    }
    let bundle = self_signed(names)?;
    fs::write(cert_path, bundle.cert.as_ref())
        .with_context(|| format!("write cert {}", cert_path.display()))?;
    fs::write(key_path, &bundle.key_der)
        .with_context(|| format!("write key {}", key_path.display()))?;
    Ok(bundle)
}

/// QUIC keep-alive PING interval (seconds). Must stay well below `QUIC_MAX_IDLE_SECS`.
pub const QUIC_KEEP_ALIVE_SECS: u64 = 15;
/// QUIC max idle timeout (seconds) — connection dies after this much inactivity.
pub const QUIC_MAX_IDLE_SECS: u64 = 30;

/// Shared QUIC transport tuning. A long-lived gRPC stream (e.g. MessageStream) sits idle
/// between messages; without an explicit keep-alive the QUIC connection hits the idle
/// timeout and dies mid-stream (observed device + gateway bug: client "open timed out",
/// server `recv_data`/`send_trailers: Connection error: Timeout`).
///
/// Tuned for **battery**, not aggressive failover. QUIC is now proven stable on
/// uncensored networks (NL testers), so we no longer need a tight idle ceiling to bail
/// out fast — the cost of that (a PING every 3s) drained battery under a system VPN,
/// where every keep-alive packet is double-encrypted and keeps the radio warm. A PING
/// every 15s with a 30s idle ceiling cuts radio wake-ups ~5× while still keeping a
/// *healthy* idle connection alive with margin against mobile jitter. Fast *connect*
/// failover is unchanged: `CONNECT_BUDGET` (1.5s, client.rs — it said 3s here until
/// 2026-08-24, when the caller turned out to decide at 1.5s and always had) still bails out
/// of a dead handshake quickly; only mid-stream death detection relaxes to ≤30s. Applied to
/// BOTH ends; the negotiated idle timeout is the min of the two.
/// Build a transport config with explicit keep-alive / idle timeouts (exposed so tests
/// can exercise the keep-alive behaviour with short timeouts).
pub fn build_transport_config(
    keep_alive: Duration,
    max_idle: Duration,
) -> Result<Arc<quinn::TransportConfig>> {
    Ok(Arc::new(tuned(keep_alive, max_idle)?))
}

fn tuned(keep_alive: Duration, max_idle: Duration) -> Result<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    tc.keep_alive_interval(Some(keep_alive));
    tc.max_idle_timeout(Some(max_idle.try_into()?));
    Ok(tc)
}

fn transport_config() -> Result<quinn::TransportConfig> {
    tuned(
        Duration::from_secs(QUIC_KEEP_ALIVE_SECS),
        Duration::from_secs(QUIC_MAX_IDLE_SECS),
    )
}

/// Bytes one connection may make the server hold, each way. quinn's defaults leave the receiving
/// side open (100 streams of 1.25 MB, `receive_window` unlimited) and allow 10 MB of unacknowledged
/// sending. 1 MiB is 10 MB/s at 100 ms.
const SERVER_CONNECTION_WINDOW: u32 = 1024 * 1024;

/// Bytes one stream may have unread, a quarter of the connection's. Were they equal, one call whose
/// upstream does not read would take the whole connection window, and the next call could not even
/// deliver its headers (RFC 9000 §4.1).
const SERVER_STREAM_WINDOW: u32 = SERVER_CONNECTION_WINDOW / 4;

/// Bound what one peer can make a server keep. Server side only: a client chose whom it talks to.
fn bound_for_server(tc: &mut quinn::TransportConfig) {
    tc.receive_window(SERVER_CONNECTION_WINDOW.into());
    tc.stream_receive_window(SERVER_STREAM_WINDOW.into());
    tc.send_window(SERVER_CONNECTION_WINDOW.into());
    // Nothing here reads QUIC datagrams; quinn would keep up to 1.25 MB of them.
    tc.datagram_receive_buffer_size(None);
}

/// Build a quinn server config that presents `bundle` and speaks h3.
pub fn server_config(bundle: &CertBundle) -> Result<quinn::ServerConfig> {
    let mut tc = transport_config()?;
    bound_for_server(&mut tc);
    server_config_tuned(bundle, Arc::new(tc))
}

/// Like `server_config` but with a caller-supplied transport config (tests).
pub fn server_config_tuned(
    bundle: &CertBundle,
    transport: Arc<quinn::TransportConfig>,
) -> Result<quinn::ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bundle.key_der.clone()));
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![bundle.cert.clone()], key)?;
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let qsc = QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    config.transport_config(transport);
    Ok(config)
}

/// Per-datagram obfuscation overhead in bytes (Salamander prepends a salt). The QUIC MTU is
/// lowered by this amount on obfuscated connections so that the obfuscated datagram
/// (`QUIC packet || salt`) never exceeds the real path MTU and gets fragmented or dropped.
pub const OBF_OVERHEAD: u16 = crate::salamander::SALT_LEN as u16;

/// Upper bound quinn's MTU discovery probes to by default. We cap obfuscated connections
/// `OBF_OVERHEAD` below this so the on-wire datagram stays within `MTUD_UPPER_BOUND`.
const MTUD_UPPER_BOUND: u16 = 1452;

/// Transport config for an obfuscated connection: same keep-alive/idle as the plain path,
/// but MTU discovery capped `OBF_OVERHEAD` lower so the salt always fits within the path MTU.
fn obf_transport_config() -> Result<quinn::TransportConfig> {
    let mut tc = transport_config()?;
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.upper_bound(MTUD_UPPER_BOUND - OBF_OVERHEAD);
    tc.mtu_discovery_config(Some(mtud));
    Ok(tc)
}

/// Build a quinn client config that trusts exactly `trust` and speaks h3.
pub fn client_config(trust: &CertBundle) -> Result<quinn::ClientConfig> {
    client_config_tuned(trust, Arc::new(transport_config()?))
}

/// Like `client_config` but with the MTU lowered for Salamander obfuscation overhead.
pub fn client_config_obf(trust: &CertBundle) -> Result<quinn::ClientConfig> {
    client_config_tuned(trust, Arc::new(obf_transport_config()?))
}

/// Like `server_config` but with the MTU lowered for Salamander obfuscation overhead.
pub fn server_config_obf(bundle: &CertBundle) -> Result<quinn::ServerConfig> {
    let mut tc = obf_transport_config()?;
    bound_for_server(&mut tc);
    server_config_tuned(bundle, Arc::new(tc))
}

/// Like `client_config` but with a caller-supplied transport config (tests).
pub fn client_config_tuned(
    trust: &CertBundle,
    transport: Arc<quinn::TransportConfig>,
) -> Result<quinn::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(trust.cert.clone())?;
    let mut tls = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let qcc = QuicClientConfig::try_from(tls)?;
    let mut config = quinn::ClientConfig::new(Arc::new(qcc));
    config.transport_config(transport);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "construct-transport-test-{}-{name}",
            std::process::id()
        ))
    }

    /// Both listeners, not only the one production runs today.
    #[test]
    fn every_server_config_is_bounded() {
        let bundle = self_signed(vec!["localhost".into()]).unwrap();
        for config in [server_config(&bundle), server_config_obf(&bundle)] {
            let shown = format!("{:?}", config.unwrap().transport);
            for want in [
                "receive_window: 1048576",
                "stream_receive_window: 262144",
                "send_window: 1048576",
                "datagram_receive_buffer_size: None",
            ] {
                assert!(shown.contains(want), "{want} not in {shown}");
            }
        }
    }

    #[test]
    fn load_or_generate_persists_then_reuses() {
        let cert = tmp("cert.der");
        let key = tmp("key.der");
        let _ = fs::remove_file(&cert);
        let _ = fs::remove_file(&key);

        // First call generates and writes both files.
        let a = load_or_generate(vec!["quic.konstruct.cc".into()], &cert, &key).unwrap();
        assert!(cert.exists() && key.exists());

        // Second call reuses the exact same cert (stable pin across restarts).
        let b = load_or_generate(vec!["quic.konstruct.cc".into()], &cert, &key).unwrap();
        assert_eq!(a.cert.as_ref(), b.cert.as_ref());
        assert_eq!(a.key_der, b.key_der);

        // A cert without its key cannot be reused → a fresh pair is generated.
        fs::remove_file(&key).unwrap();
        let c = load_or_generate(vec!["quic.konstruct.cc".into()], &cert, &key).unwrap();
        assert_ne!(a.cert.as_ref(), c.cert.as_ref());

        let _ = fs::remove_file(&cert);
        let _ = fs::remove_file(&key);
    }
}
