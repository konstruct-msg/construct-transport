//! gRPC-over-HTTP/3 length-prefix framing.
//!
//! The gRPC wire format is identical over HTTP/2 and HTTP/3:
//!
//! ```text
//!   1 byte  — compression flag (0 = uncompressed)
//!   4 bytes — message length (big-endian u32)
//!   N bytes — message body (protobuf in production; opaque bytes in this spike)
//! ```
//!
//! Mirrors `construct-engine`'s `transport::grpc` so the two stacks frame
//! identically.

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Encode a message body into a single gRPC length-prefix frame.
pub fn encode_frame(body: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(5 + body.len());
    buf.put_u8(0); // compression flag: uncompressed
    buf.put_u32(body.len() as u32);
    buf.put_slice(body);
    buf.freeze()
}

/// The largest message body this side will receive.
///
/// Not a number of our own: it is what the H2 path already enforces on iOS (the app's
/// grpc-swift-nio-transport, 2.11.0: `Connection.swift`, `defaultMaxRequestMessageSizeBytes`, which
/// despite the name bounds what its client receives) and what tonic 0.14 defaults to
/// (`codec/mod.rs`, `DEFAULT_MAX_RECV_MESSAGE_SIZE`), with the same boundary: exactly the limit is
/// allowed. A smaller one would make a message's arrival depend on which carrier was up.
pub const MAX_RECV_MESSAGE_LEN: usize = 4 * 1024 * 1024;

/// A stream's receive buffer is handed back after a message larger than this.
const RETAINED_BUFFER_LEN: usize = 64 * 1024;

/// The peer declared a message longer than [`MAX_RECV_MESSAGE_LEN`].
#[derive(Debug, thiserror::Error)]
#[error("message of {declared} bytes exceeds the limit of {MAX_RECV_MESSAGE_LEN} bytes")]
pub struct MessageTooLong {
    pub declared: usize,
}

/// Pull one complete message body (5-byte header stripped) out of `buf`, if a
/// full frame is buffered. Leaves any trailing partial frame in `buf`.
///
/// The declared length is checked as soon as the header is there, before any of the body is
/// waited for. On error `buf` is left as it is, so a refused stream stays refused.
pub fn take_frame(buf: &mut BytesMut) -> Result<Option<Bytes>, MessageTooLong> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_RECV_MESSAGE_LEN {
        return Err(MessageTooLong { declared: len });
    }
    if buf.len() < 5 + len {
        return Ok(None); // wait for more bytes
    }
    let mut frame = buf.split_to(5 + len);
    frame.advance(5); // drop the header, keep the body
    if len > RETAINED_BUFFER_LEN {
        // `BytesMut` holds its largest allocation until the handle goes. What is left here is at
        // most the tail of the last chunk read, so the copy is small.
        *buf = BytesMut::from(&buf[..]);
    }
    Ok(Some(frame.freeze()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(len: u32) -> BytesMut {
        let mut b = BytesMut::new();
        b.put_u8(0);
        b.put_u32(len);
        b
    }

    #[test]
    fn the_limit_itself_is_allowed_and_one_more_is_not() {
        let max = MAX_RECV_MESSAGE_LEN as u32;
        assert!(matches!(take_frame(&mut header(max)), Ok(None)));
        for len in [max + 1, u32::MAX] {
            let err = take_frame(&mut header(len)).expect_err("over the limit");
            assert_eq!(err.declared, len as usize);
        }
        // Four of the five header bytes say nothing yet.
        assert!(matches!(
            take_frame(&mut header(u32::MAX).split_to(4)),
            Ok(None)
        ));
    }

    /// `BytesMut` keeps its largest allocation for as long as the handle lives, so one large
    /// message used to cost its stream 6.5 MB until the stream ended.
    #[test]
    fn a_large_message_does_not_leave_its_allocation_behind() {
        let mut buf = BytesMut::from(&encode_frame(&vec![1; 1 << 20])[..]);
        buf.extend_from_slice(&encode_frame(b"next"));
        buf.extend_from_slice(&header(9)); // a partial frame after it

        let big = take_frame(&mut buf).unwrap().expect("the large message");
        assert!(big.len() == 1 << 20 && big.iter().all(|b| *b == 1));
        drop(big);

        assert!(
            !buf.try_reclaim(RETAINED_BUFFER_LEN),
            "the stream still owns the large allocation"
        );
        let next = take_frame(&mut buf).unwrap().expect("the next message");
        assert_eq!(&next[..], b"next");
        assert_eq!(buf, header(9), "the partial frame is kept");
    }
}
