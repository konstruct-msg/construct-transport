//! A QUIC connection for an h3 **server** that bounds what h3 keeps of a peer's frames.
//!
//! h3 0.0.8 leaves two things to the peer (read in its source, `frame.rs` and `proto/frame.rs`;
//! the same on its `main` as of 2026-11-25):
//!
//! * A frame other than DATA is collected whole before it is decoded, and `max_field_section_size`
//!   is checked after that. The length is a 62-bit number the peer picks, and flow control does
//!   not help: h3 reads eagerly, which returns the credit. One stream, before any authentication,
//!   could grow the process without end.
//! * Reading one DATA frame reads up to two chunks from QUIC and consumes one frame, so frames much
//!   smaller than a packet pile up inside h3 faster than they leave it.
//!
//! Both are closed here, where the bytes enter: the frame header is read as it passes, a frame
//! longer than [`MAX_BUFFERED_FRAME`] closes the connection with `H3_EXCESSIVE_LOAD` (RFC 9114
//! §8.1), and a chunk is cut at every frame boundary, so that h3 is given exactly what it consumes
//! next. Nothing is copied. DATA itself has no limit: h3 streams it, and flow control bounds it.
//!
//! **What removes this module:** an h3 release that limits the length before buffering and does not
//! read past the frame it is delivering.

use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::error::Code;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};

/// Longest frame, other than DATA, that a client may send: request headers, trailers, SETTINGS.
/// The same 64 KiB of headers the server behind this gateway accepts (`MAX_HEADER_LIST_BYTES` in
/// construct-server); the real request carries a bearer token and a few ids.
pub const MAX_BUFFERED_FRAME: u64 = 64 * 1024;

const FRAME_DATA: u64 = 0x00;
/// Not a length-prefixed frame. h3 knows it and gives the stream up to WebTransport; this gateway
/// does not speak WebTransport, so it is refused instead of being parsed as something it is not.
const FRAME_WEBTRANSPORT_BI: u64 = 0x41;
const UNI_CONTROL: u64 = 0x00;

/// A frame h3 would have had to keep, longer than [`MAX_BUFFERED_FRAME`] or without a length.
#[derive(Debug, PartialEq, Eq)]
struct Refused;

/// Follows frame boundaries in the bytes of one stream.
#[derive(Debug)]
struct Frames {
    at: At,
    /// A varint may be split between chunks.
    partial: u64,
    partial_left: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum At {
    /// First varint of a unidirectional stream.
    UniType,
    FrameType,
    FrameLen {
        data: bool,
    },
    Payload(u64),
    /// Not a stream of frames (QPACK, unknown): h3 does not buffer it.
    Opaque,
}

impl Frames {
    fn request() -> Self {
        Self::new(At::FrameType)
    }

    fn uni() -> Self {
        Self::new(At::UniType)
    }

    fn new(at: At) -> Self {
        Self {
            at,
            partial: 0,
            partial_left: 0,
        }
    }

    /// How many bytes of `buf` belong to the next piece: one frame header, or as much payload as
    /// there is. Never zero for a non-empty `buf`.
    fn next_piece(&mut self, buf: &[u8]) -> Result<usize, Refused> {
        match self.at {
            At::Opaque => return Ok(buf.len()),
            At::Payload(left) => {
                let n = left.min(buf.len() as u64);
                self.payload(left - n);
                return Ok(n as usize);
            }
            At::UniType | At::FrameType | At::FrameLen { .. } => {}
        }
        for (i, byte) in buf.iter().enumerate() {
            let Some(value) = self.varint(*byte) else {
                continue;
            };
            match self.at {
                At::UniType if value == UNI_CONTROL => self.at = At::FrameType,
                At::UniType => {
                    self.at = At::Opaque;
                    return Ok(buf.len());
                }
                At::FrameType if value == FRAME_WEBTRANSPORT_BI => return Err(Refused),
                At::FrameType => {
                    self.at = At::FrameLen {
                        data: value == FRAME_DATA,
                    }
                }
                At::FrameLen { data } => {
                    if !data && value > MAX_BUFFERED_FRAME {
                        return Err(Refused);
                    }
                    self.payload(value);
                    return Ok(i + 1);
                }
                At::Payload(_) | At::Opaque => unreachable!("handled above"),
            }
        }
        Ok(buf.len())
    }

    fn payload(&mut self, left: u64) {
        self.at = match left {
            0 => At::FrameType,
            left => At::Payload(left),
        };
    }

    /// One byte of a QUIC varint (RFC 9000 §16); the value when it is complete.
    fn varint(&mut self, byte: u8) -> Option<u64> {
        if self.partial_left == 0 {
            self.partial = u64::from(byte & 0x3f);
            self.partial_left = (1 << (byte >> 6)) - 1;
        } else {
            self.partial = self.partial << 8 | u64::from(byte);
            self.partial_left -= 1;
        }
        (self.partial_left == 0).then_some(self.partial)
    }
}

/// The h3-facing connection. Server side only: streams opened from here carry no peer frames.
pub struct Connection {
    inner: h3_quinn::Connection,
    conn: quinn::Connection,
}

impl Connection {
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            inner: h3_quinn::Connection::new(conn.clone()),
            conn,
        }
    }

    fn guard(&self, inner: h3_quinn::RecvStream, frames: Frames) -> RecvStream {
        RecvStream::new(inner, frames, self.conn.clone())
    }
}

impl quic::Connection<Bytes> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        let recv = ready!(quic::Connection::<Bytes>::poll_accept_recv(
            &mut self.inner,
            cx
        ))?;
        Poll::Ready(Ok(self.guard(recv, Frames::uni())))
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let bidi = ready!(quic::Connection::<Bytes>::poll_accept_bidi(
            &mut self.inner,
            cx
        ))?;
        Poll::Ready(Ok(BidiStream::new(bidi, self.conn.clone())))
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams {
            inner: quic::Connection::<Bytes>::opener(&self.inner),
            conn: self.conn.clone(),
        }
    }
}

macro_rules! open_streams {
    ($ty:ty) => {
        impl quic::OpenStreams<Bytes> for $ty {
            type BidiStream = BidiStream;
            type SendStream = h3_quinn::SendStream<Bytes>;

            fn poll_open_bidi(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
                let bidi = ready!(quic::OpenStreams::<Bytes>::poll_open_bidi(
                    &mut self.inner,
                    cx
                ))?;
                Poll::Ready(Ok(BidiStream::new(bidi, self.conn.clone())))
            }

            fn poll_open_send(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
                quic::OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
            }

            fn close(&mut self, code: Code, reason: &[u8]) {
                quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason)
            }
        }
    };
}

/// Opener half of [`Connection`].
pub struct OpenStreams {
    inner: h3_quinn::OpenStreams,
    conn: quinn::Connection,
}

open_streams!(Connection);
open_streams!(OpenStreams);

/// A request stream. The sending half is h3-quinn's own.
pub struct BidiStream {
    send: h3_quinn::SendStream<Bytes>,
    recv: RecvStream,
}

impl BidiStream {
    fn new(bidi: h3_quinn::BidiStream<Bytes>, conn: quinn::Connection) -> Self {
        let (send, recv) = quic::BidiStream::split(bidi);
        Self {
            send,
            recv: RecvStream::new(recv, Frames::request(), conn),
        }
    }
}

impl quic::BidiStream<Bytes> for BidiStream {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl quic::RecvStream for BidiStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl quic::SendStream<Bytes> for BidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

/// A receiving half whose bytes are followed frame by frame.
pub struct RecvStream {
    inner: h3_quinn::RecvStream,
    frames: Frames,
    /// Rest of the last chunk: read from QUIC, not yet given to h3. At most one chunk.
    rest: Bytes,
    conn: quinn::Connection,
}

impl RecvStream {
    fn new(inner: h3_quinn::RecvStream, frames: Frames, conn: quinn::Connection) -> Self {
        Self {
            inner,
            frames,
            rest: Bytes::new(),
            conn,
        }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if !self.rest.has_remaining() {
            match ready!(self.inner.poll_data(cx))? {
                Some(chunk) => self.rest = chunk,
                None => return Poll::Ready(Ok(None)),
            }
        }
        match self.frames.next_piece(&self.rest) {
            Ok(n) => Poll::Ready(Ok(Some(self.rest.split_to(n)))),
            Err(Refused) => {
                // The whole connection: no client of ours sends this, and closing it is what
                // releases the rest of what the peer has parked here.
                let code = Code::H3_EXCESSIVE_LOAD.value();
                self.conn.close(
                    quinn::VarInt::from_u64(code).expect("h3 code is a varint"),
                    b"frame too long",
                );
                Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: ConnectionErrorIncoming::Undefined(Arc::new(
                        quinn::ConnectionError::LocallyClosed,
                    )),
                }))
            }
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `wire` in chunks of `step` and return the pieces h3 would be given.
    fn pieces(mut frames: Frames, wire: &[u8], step: usize) -> Result<Vec<Vec<u8>>, Refused> {
        let mut out = vec![];
        for chunk in wire.chunks(step) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let n = frames.next_piece(rest)?;
                assert!(n > 0 && n <= rest.len());
                out.push(rest[..n].to_vec());
                rest = &rest[n..];
            }
        }
        Ok(out)
    }

    fn frame(ty: u8, len: u32) -> Vec<u8> {
        let mut f = vec![ty];
        f.extend((len | 0x8000_0000).to_be_bytes());
        f.extend(vec![0xff; len as usize]);
        f
    }

    #[test]
    fn a_header_and_its_payload_are_separate_pieces() {
        let wire = [0x00, 0x01, 0xaa, 0x00, 0x02, 0xbb, 0xbc];
        let want: Vec<Vec<u8>> = vec![
            vec![0x00, 0x01],
            vec![0xaa],
            vec![0x00, 0x02],
            vec![0xbb, 0xbc],
        ];
        assert_eq!(pieces(Frames::request(), &wire, 100).unwrap(), want);
    }

    /// Payload is 0xff, which read as a frame type would be an eight-byte varint: losing a boundary
    /// anywhere makes the following long frame look like something else.
    #[test]
    fn boundaries_survive_any_chunking_and_no_byte_is_lost() {
        let mut wire = frame(0x01, 300);
        wire.extend(frame(0x00, 0)); // empty DATA
        wire.extend(frame(0x00, 5000));
        wire.extend(frame(0x21, 7)); // grease
        let honest = wire.clone();
        let mut lying = wire;
        lying.extend([0x01]);
        lying.extend(((MAX_BUFFERED_FRAME + 1) | 0xc000_0000_0000_0000).to_be_bytes());
        for step in [1, 2, 3, 7, 64, 1200, 100_000] {
            let got = pieces(Frames::request(), &honest, step).unwrap();
            assert_eq!(got.concat(), honest, "step {step}");
            assert_eq!(pieces(Frames::request(), &lying, step), Err(Refused));
        }
    }

    #[test]
    fn the_limit_is_for_kept_frames_and_is_inclusive() {
        let len = MAX_BUFFERED_FRAME as u32;
        assert!(pieces(Frames::request(), &frame(0x01, len), 1200).is_ok());
        assert!(pieces(Frames::request(), &frame(0x01, len + 1), 1200).is_err());
        // Unknown frames are collected too before they are ignored.
        assert!(pieces(Frames::request(), &frame(0x21, len + 1), 1200).is_err());
        assert!(pieces(Frames::request(), &frame(0x00, 4 * len), 1200).is_ok());
    }

    #[test]
    fn webtransport_is_refused_and_not_parsed_as_a_length() {
        assert_eq!(
            pieces(Frames::request(), &[0x40, 0x41, 0x00], 1),
            Err(Refused)
        );
    }

    #[test]
    fn only_the_control_stream_is_a_stream_of_frames() {
        let mut control = vec![0x00];
        control.extend(frame(0x04, MAX_BUFFERED_FRAME as u32 + 1));
        assert_eq!(pieces(Frames::uni(), &control, 1), Err(Refused));
        let mut qpack = vec![0x02];
        qpack.extend(frame(0x04, MAX_BUFFERED_FRAME as u32 + 1));
        assert!(pieces(Frames::uni(), &qpack, 1).is_ok());
    }
}
