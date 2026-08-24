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
//! every `Err` alike), and the cases that must not break. The device answers the rest —
//! `udprecv_err=` in the RUNTIME line grows on a network returning ICMP errors, and CPU stays low
//! while it does.
//!
//! The send direction below is a different story: that error the OS refuses locally, so it can be
//! staged, and the test that stages it is also what proves the counter is not vacuous.

use std::io;
use std::io::IoSliceMut;
use std::net::UdpSocket;
use std::sync::Arc;

use construct_transport::spin_free_socket::{
    RecvDisposition, SendDisposition, SpinFreeUdpSocket, send_errors,
};
use quinn::AsyncUdpSocket;
use quinn::udp::{RecvMeta, Transmit};

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

// MARK: - The send direction (nothing counted it until 2026-08-24)

#[test]
fn a_send_that_cannot_succeed_is_counted() {
    for kind in [
        io::ErrorKind::AddrNotAvailable, // the wrong-address-family case, TODO 59
        io::ErrorKind::InvalidInput,     // how Darwin can surface the same thing
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::BrokenPipe,
    ] {
        let result: io::Result<()> = Err(kind.into());
        assert_eq!(
            SendDisposition::of(&result),
            SendDisposition::Failed,
            "{kind:?} means the datagram did not leave — this is the run that read as udperr=0"
        );
    }
}

#[test]
fn an_mtu_probe_is_not_a_send_failure() {
    // Must NOT count. Every connection probes the path MTU with a datagram it expects to be
    // rejected, so counting EMSGSIZE would report steady send failure on a perfectly healthy link
    // — the inversion that made `chunk_reassembly_incomplete` unusable.
    let result: io::Result<()> = Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    assert_eq!(SendDisposition::of(&result), SendDisposition::ProbeTooLarge);
}

#[test]
fn backpressure_is_not_a_send_failure() {
    // Must NOT count: quinn retries when the write poller reports writable. Counting it would make
    // a busy uplink indistinguishable from a socket that cannot send, which is the exact confusion
    // this counter was added to end.
    let result: io::Result<()> = Err(io::ErrorKind::WouldBlock.into());
    assert_eq!(SendDisposition::of(&result), SendDisposition::WouldBlock);
}

#[test]
fn a_successful_send_is_not_counted() {
    assert_eq!(SendDisposition::of(&Ok(())), SendDisposition::Sent);
}

/// The staged version of TODO 59, which the classification tests above cannot reach: a socket
/// bound to one address family, asked to send to the other. This is what the device did for three
/// runs while the RUNTIME line said the socket was fine.
///
/// Unlike the receive side — where macOS declines to deliver the ICMP over loopback, so the error
/// could not be staged at all — this one the OS refuses locally and synchronously.
#[tokio::test(flavor = "current_thread")]
async fn a_wrong_family_destination_increments_the_counter() {
    let socket =
        Arc::new(SpinFreeUdpSocket::bind("127.0.0.1:0".parse().expect("v4 addr")).expect("bind v4"));

    // Wait for write readiness first. `try_io` short-circuits to `WouldBlock` without running the
    // closure while readiness is unknown, so a bare `try_send` on a fresh socket reports
    // backpressure and never reaches the OS — the first version of this test asserted on that and
    // read it as the counter failing.
    let mut poller = socket.clone().create_io_poller();
    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .expect("socket becomes writable");

    let before = send_errors();
    let result = socket.try_send(&Transmit {
        destination: "[::1]:9".parse().expect("v6 addr"),
        ecn: None,
        contents: b"unsendable",
        segment_size: None,
        src_ip: None,
    });

    // The return value is deliberately `Ok(())` — one lost datagram must not fail a QUIC
    // connection, and that was the behaviour before this counter existed. The counter is the
    // entire observable difference, which is also why asserting on the return value here would
    // prove nothing.
    assert!(result.is_ok(), "a lost datagram must not be raised to quinn");
    assert_eq!(
        send_errors(),
        before + 1,
        "the failure must be counted — an uncounted one is what `udperr=0` was hiding"
    );
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
