# Multi-stage build for the construct-transport QUIC/H3 service.
# Phase 0: the image runs the echo server (network-reachability test).
# Phase 0.5: the h3->envoy gateway binary will be added and selected via CMD.
#
# Pure-ring crypto (no aws-lc-rs) → no cmake/clang needed in the builder.

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/construct-transport /usr/local/bin/construct-transport

# QUIC is UDP. Bind defaults to 0.0.0.0:4433 (override via CMD / compose).
EXPOSE 4433/udp
ENTRYPOINT ["/usr/local/bin/construct-transport"]
CMD ["0.0.0.0:4433"]
