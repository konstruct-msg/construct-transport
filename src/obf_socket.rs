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
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, ServerConfig, UdpPoller};
use rand::RngCore;

use crate::salamander::{SALT_LEN, Salamander};
use crate::spin_free_socket::SpinFreeUdpSocket;

/// Build the UDP socket an endpoint runs on: spin-free always, obfuscated when a PSK is in play.
///
/// One builder for the first socket and for every replacement `Endpoint::rebind_abstract` is
/// handed. Those are two carriers of one fact — how this connection's datagrams look on the wire —
/// and the disagreement has no error path: a plain socket rebound under an obfuscated connection
/// sends every datagram in the clear to a gateway that discards them as garbage, so the symptom is
/// a connection that simply stops, on the one code path (a network handover) where stopping is
/// already the expected background noise.
pub fn client_socket(bind: SocketAddr, obf: Option<&Salamander>) -> io::Result<ClientSocket> {
    // NOT `runtime.wrap_udp_socket`: quinn's own socket spins a core when recvmsg reports an
    // error other than WouldBlock (see spin_free_socket). The obfuscated wrapper delegates
    // poll_recv straight to the inner socket, so it inherits whichever bug the inner socket has —
    // and, for the same reason, its per-socket receive counter.
    let base = Arc::new(SpinFreeUdpSocket::bind(bind)?);
    let endpoint_socket: Arc<dyn AsyncUdpSocket> = match obf {
        Some(obf) => Arc::new(ObfuscatedUdpSocket::new(base.clone(), obf.clone())),
        None => base.clone(),
    };
    Ok(ClientSocket {
        endpoint_socket,
        base,
    })
}

/// A freshly built client socket, and a handle to the thing underneath it that counts.
///
/// Two views of one socket rather than two sockets: `endpoint_socket` is what quinn runs on and
/// may be the obfuscating wrapper, `base` is the same socket seen from below, and it is the only
/// place that can answer "did anything arrive **here**" — which is what `QuicClient::rebind` needs
/// and what the connection-level counters cannot tell it.
pub struct ClientSocket {
    pub endpoint_socket: Arc<dyn AsyncUdpSocket>,
    pub base: Arc<SpinFreeUdpSocket>,
}

fn obfuscated_endpoint(
    bind: SocketAddr,
    obf: Salamander,
    server_config: Option<ServerConfig>,
) -> io::Result<Endpoint> {
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime for QUIC endpoint"))?;
    let socket = client_socket(bind, Some(&obf))?.endpoint_socket;
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
