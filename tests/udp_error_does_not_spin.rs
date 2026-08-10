//! A UDP receive error must not pin a CPU core.
//!
//! Device, 2026-08-10: a **live, healthy** QUIC connection (`transport=conns=1 tasks=5`, packets
//! flowing both ways) with the app at 111% CPU and thermal state `serious`. Time Profiler put
//! 1.43 minutes of a 1.59 minute trace in `__recvmsg`, under
//! `EndpointDriver::poll → RecvState::poll_socket → try_io → quinn_udp::recv`.
//!
//! quinn's `poll_recv` loops on any receive error that is not `WouldBlock`, and tokio's `try_io`
//! clears socket readiness only for `WouldBlock` — so the driver is re-polled instantly, forever.
//! On Darwin an ICMP unreachable arrives as exactly that kind of pending socket error.
//!
//! The earlier `Endpoint::close` fix does not cover this: nothing here is being torn down.
//!
//! # What is and is not covered
//!
//! **Not covered: staging a real receive error.** A first version of this file connected a UDP
//! socket to a dead local port, sent to it, and asserted the driver parked. It passed — and it
//! passed vacuously: a probe assertion (`suppressed_socket_errors() > before`) showed the counter
//! never moved, so `poll_recv` returned `Pending` because the socket was empty, not because it had
//! handled anything. macOS does not deliver that ICMP back over loopback. A test that green-lights
//! the fix without ever exercising it is worse than none, so it was removed rather than kept.
//!
//! Covered instead: the classification, which is where the defect actually lives (quinn treats
//! every `Err` alike), and the cases that must not break. The device answers the rest — `udperr=`
//! in the RUNTIME line grows on a network returning ICMP errors, and CPU stays low while it does.

use std::io;
use std::io::IoSliceMut;
use std::net::UdpSocket;
use std::sync::Arc;

use construct_transport::spin_free_socket::{RecvDisposition, SpinFreeUdpSocket};
use quinn::AsyncUdpSocket;
use quinn::udp::RecvMeta;

// MARK: - The classification (this is the defect)

#[test]
fn a_real_socket_error_must_clear_readiness_before_parking() {
    // The whole bug in one assertion. quinn's loop treats these identically to WouldBlock, and
    // because try_io left the socket marked ready, the next poll returns instantly — forever.
    for kind in [
        io::ErrorKind::ConnectionRefused, // ICMP port unreachable — the Darwin case
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::Other,
    ] {
        let result: io::Result<usize> = Err(kind.into());
        assert_eq!(
            RecvDisposition::of(&result),
            RecvDisposition::ClearReadinessThenPark,
            "{kind:?} must clear readiness — this is the 111% CPU / thermal `serious` case"
        );
    }
}

#[test]
fn would_block_parks_without_clearing_readiness_again() {
    // Must NOT fire: try_io has already cleared readiness here. Clearing it again would add a
    // wasted syscall to the hottest path in the transport, once per empty poll.
    let result: io::Result<usize> = Err(io::ErrorKind::WouldBlock.into());
    assert_eq!(RecvDisposition::of(&result), RecvDisposition::Park);
}

#[test]
fn datagrams_are_delivered_not_swallowed() {
    // Must NOT fire: a socket that treated success as an error would look exactly like the fix
    // working — low CPU, no spin — while taking QUIC down completely.
    assert_eq!(RecvDisposition::of(&Ok(3)), RecvDisposition::Deliver(3));
    assert_eq!(RecvDisposition::of(&Ok(0)), RecvDisposition::Deliver(0));
}

// MARK: - The socket still works

#[tokio::test(flavor = "current_thread")]
async fn a_healthy_socket_still_receives() {
    let receiver_std = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    let recv_addr = receiver_std.local_addr().expect("addr");
    let receiver = Arc::new(SpinFreeUdpSocket::wrap(receiver_std).expect("wrap receiver"));

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender.send_to(b"hello", recv_addr).expect("send");

    let mut storage = [0u8; 2048];
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [RecvMeta::default()];

    let n = std::future::poll_fn(|cx| receiver.poll_recv(cx, &mut bufs, &mut meta))
        .await
        .expect("poll_recv");

    assert_eq!(n, 1, "one datagram was sent and must be received");
    assert_eq!(&bufs[0][..meta[0].len], b"hello");
}

#[tokio::test(flavor = "current_thread")]
async fn an_empty_socket_parks() {
    // The ordinary path: nothing to read, no error, and it must not busy-loop either.
    let sock = Arc::new(
        SpinFreeUdpSocket::wrap(UdpSocket::bind("127.0.0.1:0").expect("bind")).expect("wrap"),
    );
    let mut storage = [0u8; 2048];
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [RecvMeta::default()];

    let waker = std::task::Waker::noop().clone();
    let mut cx = std::task::Context::from_waker(&waker);
    assert!(sock.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
}
