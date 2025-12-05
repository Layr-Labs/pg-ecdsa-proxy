# Build stage for Rust proxy
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

# Runtime stage with Postgres + Proxy
FROM postgres:16-bookworm

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the proxy binary
COPY --from=builder /app/target/release/postgres-ecdsa-proxy /usr/local/bin/proxy

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy init SQL
COPY sql/init.sql /docker-entrypoint-initdb.d/init.sql

# Environment defaults
# Note: POSTGRES_USER/PASSWORD and PG_USER/PASSWORD are auto-generated at runtime
# for security. Set PG_RANDOM_CREDS=false to use custom credentials.
ENV POSTGRES_DB=postgres \
    PG_HOST=localhost \
    PG_PORT=5432 \
    PG_DATABASE=postgres \
    PROXY_HOST=0.0.0.0 \
    PROXY_PORT=5433 \
    PG_RANDOM_CREDS=true

# Expose proxy port (Postgres 5432 is internal only)
EXPOSE 5433

ENTRYPOINT ["/entrypoint.sh"]
