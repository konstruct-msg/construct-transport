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
//! Errors are counted, not hidden: `suppressed_recv_errors()` feeds the `transport=` field of
//! the device RUNTIME line, so a recurrence is visible instead of being inferred from a thermal
//! reading.
//!
//! # The other direction
//!
//! That counter is about **receiving**, and until 2026-08-24 it was the only one, under a name
//! (`suppressed_socket_errors`, printed as `udperr`) that reads as though it covered the socket.
//! An endpoint bound to the wrong address family could not send a single datagram and the line
//! still said `udperr=0` — true, and taken for three device runs as evidence the socket was
//! healthy. `send_errors()` counts the other half, reported beside it and never summed into it.

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
static SUPPRESSED_RECV_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Total non-`WouldBlock` send failures since process start, across all endpoints.
static SEND_ERRORS: AtomicU64 = AtomicU64::new(0);

/// How many receive errors have been absorbed without spinning. Steady growth means the network
/// is returning ICMP errors; the point is that it no longer costs a core.
///
/// Named for the direction on purpose. It was `suppressed_socket_errors`, which reads as "socket
/// errors" and counts half of them — the naming half of the defect below.
pub fn suppressed_recv_errors() -> u64 {
    SUPPRESSED_RECV_ERRORS.load(Ordering::Relaxed)
}

/// How many datagrams failed to leave the socket.
///
/// Exists because for three device runs nothing counted this. The endpoint had bound the wrong
/// address family and could not send a single datagram, while the RUNTIME line reported
/// `udperr=0` — a true statement about receiving, read as "the socket is fine". A gauge named for
/// UDP errors that counts one direction answers a question nobody asked, and its answer is
/// reassuring. Kept separate from the receive counter rather than summed: "nothing arrives" and
/// "nothing leaves" are different diagnoses, and adding them reproduces the lost distinction.
pub fn send_errors() -> u64 {
    SEND_ERRORS.load(Ordering::Relaxed)
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

/// What one `send` attempt means for the send-error counter.
///
/// Lifted out for the same reason as `RecvDisposition`: the thing that can be wrong here is the
/// classification, not the algorithm. Two of the four cases must **not** be counted, and both are
/// ordinary traffic — counting either would put a healthy connection into the gauge and bury the
/// case it exists for, which is the inversion `ios-semantic-divergence-signals` rule 1a is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendDisposition {
    /// The datagram left the socket.
    Sent,
    /// Backpressure, not a failure. quinn retries when the write poller reports writable.
    WouldBlock,
    /// `EMSGSIZE` — a path-MTU probe that was deliberately too large. Every connection makes
    /// these, and quinn treats them as success (`quinn_udp::UdpSocketState::send`). Counting them
    /// would report MTU discovery as send failure on every healthy connection.
    ProbeTooLarge,
    /// The datagram did not leave and will not: no route, wrong address family, socket shut down.
    Failed,
}

impl SendDisposition {
    pub fn of(result: &io::Result<()>) -> Self {
        match result {
            Ok(()) => Self::Sent,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Self::WouldBlock,
            Err(e) if e.raw_os_error() == Some(libc::EMSGSIZE) => Self::ProbeTooLarge,
            Err(_) => Self::Failed,
        }
    }
}

pub struct SpinFreeUdpSocket {
    io: tokio::net::UdpSocket,
    inner: udp::UdpSocketState,
    /// Datagrams delivered **on this socket**, as opposed to on the connection.
    ///
    /// Per-instance on purpose. `QuicClient::rebind` has to answer "did the peer reply to us at
    /// the new address", and the connection-level counter cannot: quinn keeps the previous socket
    /// alive for a while after a rebind (`Endpoint::rebind_abstract` stores it in `prev_socket`),
    /// so a packet already in flight to the old address arrives, increments the connection's
    /// `udp_rx`, and looks exactly like a successful migration. That false positive was observed
    /// while building the migration test, not reasoned about afterwards.
    received: AtomicU64,
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
            received: AtomicU64::new(0),
        })
    }

    /// Datagrams this socket has delivered to quinn. See the field.
    pub fn received_datagrams(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
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

    /// Sends, and — unlike every version before 2026-08-24 — notices when it could not.
    ///
    /// This calls `quinn_udp`'s `try_send`, not its `send`, and the difference is the whole point.
    /// `send` maps every error except `WouldBlock` to `Ok(())` (`unix.rs:207`): it logs through the
    /// `log` crate and reports success. So a counter written the obvious way — classify the result
    /// of `send` — would have read zero on a socket that could not transmit at all, which is the
    /// same false reassurance as the missing counter, dressed as a fix.
    ///
    /// What we return to quinn is unchanged: `Ok(())` for the swallowed classes, the `WouldBlock`
    /// through so the write poller does its job. A single lost datagram must not fail a connection
    /// — QUIC recovers from that by design — so the swallow policy is reproduced deliberately here
    /// rather than tightened as a side effect of adding a gauge.
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        let result = self.io.try_io(Interest::WRITABLE, || {
            self.inner.try_send((&self.io).into(), transmit)
        });

        match SendDisposition::of(&result) {
            SendDisposition::Sent | SendDisposition::ProbeTooLarge => Ok(()),
            SendDisposition::WouldBlock => result,
            SendDisposition::Failed => {
                SEND_ERRORS.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
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
                RecvDisposition::Deliver(n) => {
                    self.received.fetch_add(n as u64, Ordering::Relaxed);
                    return Poll::Ready(Ok(n));
                }
                RecvDisposition::Park => continue,
                RecvDisposition::ClearReadinessThenPark => {
                    // THE HEAT. try_io did NOT clear readiness for this error, so returning to the
                    // top of the loop would find the socket "ready" again instantly and burn a
                    // core. Report WouldBlock without doing any I/O — that is what tells tokio the
                    // socket is not actually ready — then park like any other empty socket.
                    SUPPRESSED_RECV_ERRORS.fetch_add(1, Ordering::Relaxed);
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
