//! construct-transport — QUIC/HTTP-3 gRPC transport for Construct Messenger.
//!
//! **Phase 0 (diagnostic spike).** This crate currently contains only the
//! minimum needed to prove that bidirectional gRPC-over-HTTP/3 works on a
//! native quinn+h3 server — the exact path that silent-failed through the
//! Traefik QUIC↔h2c bridge in 2026-05 (see
//! `construct-docs/decisions/quic-h3-transport-dedicated-rust-stack.md`).
//!
//! The real transport-only FFI surface (`open_grpc_stream` / `send` / `recv` /
//! `close`) lands in Phase 1 once Phase 0 confirms the wire path.

pub mod client;
pub mod echo_server;
pub mod ffi;
pub mod grpc;
pub mod proxy;
pub mod tls;

uniffi::setup_scaffolding!();
