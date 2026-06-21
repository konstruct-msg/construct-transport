# Multi-stage build for the construct-transport QUIC/H3 service.
#
# Ships three binaries:
#   gateway              — h3 -> h2c reverse proxy to envoy (the real service); DEFAULT
#   construct-transport  — echo server (Phase 0 reachability test)
#   probe                — client probe (diagnostics)
#
# Pure-ring crypto (no aws-lc-rs) → no cmake/clang needed in the builder.

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bins

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/gateway /usr/local/bin/gateway
COPY --from=builder /build/target/release/construct-transport /usr/local/bin/construct-transport
COPY --from=builder /build/target/release/probe /usr/local/bin/probe

# QUIC is UDP. The gateway reads QUIC_BIND / QUIC_UPSTREAM / QUIC_SAN from env.
EXPOSE 443/udp
ENTRYPOINT ["/usr/local/bin/gateway"]
