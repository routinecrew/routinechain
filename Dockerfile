FROM rust:1.82-slim AS builder

RUN apt-get update && apt-get install -y \
    clang libclang-dev llvm-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --bin rc-node

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/rc-node /usr/local/bin/rcw

RUN mkdir -p /var/lib/rcw /etc/rcw

EXPOSE 26656 26657

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -sf http://localhost:26657/status || exit 1

ENTRYPOINT ["rcw"]
CMD ["start", "--config", "/etc/rcw/config.yml"]
