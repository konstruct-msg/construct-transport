//! TLS / certificate plumbing for the Phase 0 spike.
//!
//! Generates a self-signed cert (rcgen) and builds quinn client/server configs
//! with the `h3` ALPN. The client trusts exactly the spike's own cert, so we
//! avoid a dangerous "accept any cert" verifier even in tests.

use std::sync::Arc;

use anyhow::Result;
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

/// Build a quinn server config that presents `bundle` and speaks h3.
pub fn server_config(bundle: &CertBundle) -> Result<quinn::ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bundle.key_der.clone()));
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![bundle.cert.clone()], key)?;
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let qsc = QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(qsc)))
}

/// Build a quinn client config that trusts exactly `trust` and speaks h3.
pub fn client_config(trust: &CertBundle) -> Result<quinn::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(trust.cert.clone())?;
    let mut tls = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let qcc = QuicClientConfig::try_from(tls)?;
    Ok(quinn::ClientConfig::new(Arc::new(qcc)))
}
