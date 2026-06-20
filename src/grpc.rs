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

/// Pull one complete message body (5-byte header stripped) out of `buf`, if a
/// full frame is buffered. Leaves any trailing partial frame in `buf`.
pub fn take_frame(buf: &mut BytesMut) -> Option<Bytes> {
    if buf.len() < 5 {
        return None;
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if buf.len() < 5 + len {
        return None; // wait for more bytes
    }
    let mut frame = buf.split_to(5 + len);
    frame.advance(5); // drop the header, keep the body
    Some(frame.freeze())
}
