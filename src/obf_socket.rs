//! `ObfuscatedUdpSocket` — a `quinn::AsyncUdpSocket` that wraps another socket and applies
//! Salamander obfuscation to every datagram (send: obfuscate; recv: deobfuscate). Used
//! identically on the client and the gateway, so QUIC itself is untouched — only the bytes on
//! the wire change, defeating DPI fingerprinting of QUIC.
//!
//! GSO/GRO are disabled (`max_*_segments = 1`) so each `Transmit`/`RecvMeta` is exactly one
//! datagram, which keeps the per-packet obfuscation simple and correct. The +8-byte salt is
//! accounted for by lowering the QUIC MTU at the endpoint (see callers).

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, ServerConfig, UdpPoller};
use rand::RngCore;

use crate::salamander::{SALT_LEN, Salamander};

fn obfuscated_endpoint(
    bind: SocketAddr,
    obf: Salamander,
    server_config: Option<ServerConfig>,
) -> io::Result<Endpoint> {
    let runtime = quinn::default_runtime().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "no async runtime for QUIC endpoint")
    })?;
    let std_socket = std::net::UdpSocket::bind(bind)?;
    let inner = runtime.wrap_udp_socket(std_socket)?;
    let socket = Arc::new(ObfuscatedUdpSocket::new(inner, obf));
    Endpoint::new_with_abstract_socket(EndpointConfig::default(), server_config, socket, runtime)
}

/// Build a client endpoint whose datagrams are Salamander-obfuscated.
pub fn obfuscated_client_endpoint(bind: SocketAddr, obf: Salamander) -> io::Result<Endpoint> {
    obfuscated_endpoint(bind, obf, None)
}

/// Build a server endpoint that deobfuscates incoming datagrams (and obfuscates replies).
pub fn obfuscated_server_endpoint(
    bind: SocketAddr,
    obf: Salamander,
    server_config: ServerConfig,
) -> io::Result<Endpoint> {
    obfuscated_endpoint(bind, obf, Some(server_config))
}

pub struct ObfuscatedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obf: Salamander,
}

impl ObfuscatedUdpSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, obf: Salamander) -> Self {
        Self { inner, obf }
    }
}

impl fmt::Debug for ObfuscatedUdpSocket {
    // Never print the PSK.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfuscatedUdpSocket")
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for ObfuscatedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // GSO disabled (max_transmit_segments == 1) → `contents` is a single datagram.
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut buf = vec![0u8; transmit.contents.len() + SALT_LEN];
        self.obf.obfuscate(transmit.contents, salt, &mut buf);
        let obfuscated = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buf,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&obfuscated)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => {
                // GRO disabled (max_receive_segments == 1) → one datagram per filled buffer.
                for i in 0..n {
                    let len = meta[i].len;
                    match self.obf.deobfuscate_in_place(&mut bufs[i][..], len) {
                        Some(plain_len) => {
                            meta[i].len = plain_len;
                            meta[i].stride = plain_len;
                        }
                        None => {
                            // Too short to be one of ours — drop it (quinn ignores len 0).
                            meta[i].len = 0;
                            meta[i].stride = 0;
                        }
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    // Single datagram per transmit/recv so the per-packet obfuscation stays simple.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
