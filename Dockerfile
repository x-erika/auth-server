FROM rust:1-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src target/release/auth-server target/release/auth-server.d \
           target/release/deps/auth_server* target/release/.fingerprint/auth-server-*

COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/auth-server /usr/local/bin/auth-server

RUN mkdir -p /data/keys && chmod 700 /data/keys

ENV \
    HTTP_HOST=0.0.0.0 \
    HTTP_PORT=8080 \
    AUTH_JWT_KEYS_DIR=/data/keys

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/auth-server"]
