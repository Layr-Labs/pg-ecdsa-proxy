# Build stage
FROM rust:1.86-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./

# Cache dependencies
RUN mkdir src && echo "fn main() {println!(\"placeholder\");}" > src/main.rs
RUN cargo build --release && rm -rf src target/release/postgres-ecdsa-proxy target/release/deps/postgres_ecdsa_proxy*

COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/postgres-ecdsa-proxy /app/proxy

EXPOSE 5433
CMD ["/app/proxy"]

