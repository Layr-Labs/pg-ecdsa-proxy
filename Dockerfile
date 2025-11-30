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

# Get pg_dump from postgres Debian image (not Alpine)
FROM postgres:16-bookworm AS pg

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpq5 \
    libreadline8 \
    && rm -rf /var/lib/apt/lists/*

# Copy postgres tools from postgres Debian image
COPY --from=pg /usr/lib/postgresql/16/bin/pg_dump /usr/bin/pg_dump
COPY --from=pg /usr/lib/postgresql/16/bin/pg_restore /usr/bin/pg_restore
COPY --from=pg /usr/lib/postgresql/16/bin/psql /usr/bin/psql

WORKDIR /app
COPY --from=builder /app/target/release/postgres-ecdsa-proxy /app/proxy

EXPOSE 5433
CMD ["/app/proxy"]
