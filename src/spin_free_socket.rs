//! A UDP socket for quinn that does not pin a CPU core when the socket reports an error.
//!
//! # The bug this exists for
//!
//! quinn 0.11.9 (and 0.11.11 — upstream has not changed it) implements `poll_recv` like this:
//!
//! ```ignore
//! loop {
//!     ready!(self.io.poll_recv_ready(cx))?;
//!     if let Ok(res) = self.io.try_io(Interest::READABLE, || self.inner.recv(...)) {
//!         return Poll::Ready(Ok(res));
//!     }
//!     // any Err other than WouldBlock falls through and loops again
//! }
//! ```
//!
//! `tokio`'s `try_io` clears the socket's readiness **only** when the closure reports
//! `WouldBlock`. Any other error leaves the socket marked ready, so `poll_recv_ready` returns
//! `Ready` immediately, `recvmsg` fails the same way again, and the endpoint driver spins as fast
//! as the CPU allows — for as long as the app is foregrounded.
//!
//! On Darwin a UDP socket surfaces ICMP unreachables as a pending socket error, which is exactly
//! the shape of error that hits this path. The connection itself keeps working; one core simply
//! burns beside it.
//!
//! Device evidence, iPhone, Time Profiler, 2026-08-10 — with a **live, healthy** QUIC connection
//! (`transport=conns=1 tasks=5`, `tx_pkts`/`rx_pkts` both climbing) and the app at 111% CPU,
//! thermal state `serious`:
//!
//! ```text
//!   quinn::endpoint::EndpointDriver::poll          86.9%
//!     RecvState::poll_socket                       86.8%
//!       UdpSocket::poll_recv                       86.6%
//!         tokio Registration::try_io               84.5%
//!           quinn_udp::UdpSocketState::recv        83.3%
//!             __recvmsg                            82.1%   ← 1.43 min of SELF time
//!             cerror                                0.6%
//!           std::io::error::Error::kind             0.4%   ← the WouldBlock check
//! ```
//!
//! An earlier fix (`Endpoint::close` on teardown, 2026-08-10) addressed a different case — an
//! endpoint left running after a failed handshake — and did not touch this one, because here
//! nothing is being torn down. The connection is in use and expected to stay.
//!
//! # The fix
//!
//! On a non-`WouldBlock` error, tell tokio the socket is not ready before looping. A closure that
//! reports `WouldBlock` without performing any I/O is precisely how `try_io` is documented to be
//! told that — it clears readiness and the driver parks until the next kqueue event instead of
//! re-polling immediately.
//!
//! The error itself is consumed by the failed `recvmsg` (BSD socket-error semantics), so this
//! costs one wasted syscall per error rather than millions.
//!
//! Errors are counted, not hidden: `suppressed_socket_errors()` feeds the `transport=` field of
//! the device RUNTIME line, so a recurrence is visible instead of being inferred from a thermal
//! reading.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use quinn::udp;
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::Interest;

/// Total non-`WouldBlock` receive errors swallowed since process start, across all endpoints.
static SUPPRESSED_ERRORS: AtomicU64 = AtomicU64::new(0);

/// How many receive errors have been absorbed without spinning. Steady growth means the network
/// is returning ICMP errors; the point is that it no longer costs a core.
pub fn suppressed_socket_errors() -> u64 {
    SUPPRESSED_ERRORS.load(Ordering::Relaxed)
}

/// What `poll_recv` must do with the result of one `recv` attempt.
///
/// Lifted out of the polling loop because the bug is a classification, not an algorithm: quinn
/// treats every `Err` alike, and only one of them has had its readiness cleared. Whether an error
/// can be staged on a given OS is a property of that OS; whether we react correctly to it is a
/// property of this function, and that is the part worth pinning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvDisposition {
    /// Datagrams were read; hand them to quinn.
    Deliver(usize),
    /// `try_io` already cleared readiness for us. Loop and park.
    Park,
    /// A real socket error — Darwin surfaces ICMP unreachables this way. `try_io` did **not**
    /// clear readiness, so looping without clearing it re-polls immediately and pins a core.
    ClearReadinessThenPark,
}

impl RecvDisposition {
    pub fn of(result: &io::Result<usize>) -> Self {
        match result {
            Ok(n) => Self::Deliver(*n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Self::Park,
            Err(_) => Self::ClearReadinessThenPark,
        }
    }
}

pub struct SpinFreeUdpSocket {
    io: tokio::net::UdpSocket,
    inner: udp::UdpSocketState,
}

impl fmt::Debug for SpinFreeUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpinFreeUdpSocket")
            .field("local_addr", &self.io.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl SpinFreeUdpSocket {
    /// Bind and wrap. Must be called from inside a tokio runtime — `tokio::net::UdpSocket`
    /// registers with the reactor.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        Self::wrap(socket)
    }

    pub fn wrap(socket: std::net::UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: udp::UdpSocketState::new((&socket).into())?,
            io: tokio::net::UdpSocket::from_std(socket)?,
        })
    }
}

/// Write-readiness poller. quinn's own helper for this is private, and `poll_send_ready` does the
/// same job without an owned future.
struct WritablePoller(Arc<SpinFreeUdpSocket>);

impl fmt::Debug for WritablePoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WritablePoller").finish_non_exhaustive()
    }
}

impl UdpPoller for WritablePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for SpinFreeUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(WritablePoller(self))
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let result = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            });

            match RecvDisposition::of(&result) {
                RecvDisposition::Deliver(n) => return Poll::Ready(Ok(n)),
                RecvDisposition::Park => continue,
                RecvDisposition::ClearReadinessThenPark => {
                    // THE HEAT. try_io did NOT clear readiness for this error, so returning to the
                    // top of the loop would find the socket "ready" again instantly and burn a
                    // core. Report WouldBlock without doing any I/O — that is what tells tokio the
                    // socket is not actually ready — then park like any other empty socket.
                    SUPPRESSED_ERRORS.fetch_add(1, Ordering::Relaxed);
                    let _ = self.io.try_io(Interest::READABLE, || {
                        Err::<(), io::Error>(io::ErrorKind::WouldBlock.into())
                    });
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}
